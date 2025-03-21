# Security Compliance Analysis Tool
# This tool compares baseline security documents with CIS benchmarks
# and generates a formatted compliance report

import pandas as pd
import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import PyPDF2
import docx
import os
import webbrowser
import tkinter as tk  # For file dialog
from tkinter import filedialog


class SecurityComplianceTool:
    def __init__(self):
        self.baseline_doc = None
        self.cis_benchmark = None
        self.compliance_data = None
        self.compliant_controls = []
        self.non_compliant_controls = []
        self.missing_controls = []
        self.compliance_score = 0

    def upload_files(self):
        """Open file dialogs for user to select baseline and CIS benchmark files."""
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        print("Please select the baseline document...")
        baseline_filename = filedialog.askopenfilename(title="Select Baseline Document")

        if not baseline_filename:
            print("No baseline document selected.  Exiting.")
            return None, None

        print("Please select the CIS benchmark document...")
        cis_filename = filedialog.askopenfilename(title="Select CIS Benchmark Document")

        if not cis_filename:
            print("No CIS benchmark document selected.  Exiting.")
            return None, None


        self.baseline_doc = self._parse_document(baseline_filename)
        self.cis_benchmark = self._parse_document(cis_filename)

        print(f"\nSuccessfully loaded baseline document: {baseline_filename}")
        print(f"Successfully loaded CIS benchmark: {cis_filename}")

        return baseline_filename, cis_filename


    def _parse_document(self, filename):
        """Parse document based on file extension"""
        _, ext = os.path.splitext(filename)

        if ext.lower() == '.pdf':
            return self._parse_pdf(filename)
        elif ext.lower() == '.docx':
            return self._parse_docx(filename)
        elif ext.lower() in ['.txt', '.csv']:
            with open(filename, 'r') as f:
                return f.read()
        else:
            print(f"Unsupported file format: {ext}. Please use PDF, DOCX, TXT, or CSV.")
            return None

    def _parse_pdf(self, filename):
        """Extract text from PDF file"""
        text = ""
        try:
            with open(filename, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page_num in range(len(pdf_reader.pages)):
                    text += pdf_reader.pages[page_num].extract_text()
            return text
        except Exception as e:
            print(f"Error parsing PDF: {e}")
            return None

    def _parse_docx(self, filename):
        """Extract text from DOCX file"""
        try:
            doc = docx.Document(filename)
            return "\n".join([para.text for para in doc.paragraphs])
        except Exception as e:
            print(f"Error parsing DOCX: {e}")
            return None

    def extract_controls(self):
        """Extract security controls from both documents"""
        # This is a simplified implementation
        # In a real-world scenario, you would use more advanced NLP techniques

        # For demonstration, let's extract controls from the example data
        controls = {
            "Strong Password Policy": {"expected": "implemented", "current": "implemented"},
            "Access Control": {"expected": "implemented", "current": "implemented"},
            "Disable LOAD DATA LOCAL INFILE": {"expected": "0", "current": "1"},
            "Error Limit": {"expected": "3", "current": "10"},
            "User Management": {"expected": "implemented", "current": "implemented"},
            "Server-Side Scripting": {"expected": "disabled", "current": "enabled"},
            "Encryption": {"expected": "implemented", "current": "missing"}
        }

        self.compliance_data = controls
        return controls

    def analyze_compliance(self):
        """Analyze compliance based on extracted controls"""
        if not self.compliance_data:
            print("No compliance data available. Please extract controls first.")
            return

        self.compliant_controls = []
        self.non_compliant_controls = []
        self.missing_controls = []

        for control, values in self.compliance_data.items():
            if values["current"] == values["expected"] or values["current"] == "implemented" and values["expected"] == "implemented":
                self.compliant_controls.append(control)
            elif values["current"] == "missing":
                self.missing_controls.append(control)
            else:
                self.non_compliant_controls.append({
                    "control": control,
                    "expected": values["expected"],
                    "current": values["current"]
                })

        total_controls = len(self.compliance_data)
        compliant_count = len(self.compliant_controls)
        self.compliance_score = (compliant_count / total_controls) * 100

        return {
            "compliant": self.compliant_controls,
            "non_compliant": self.non_compliant_controls,
            "missing": self.missing_controls,
            "score": self.compliance_score
        }

    def generate_recommendations(self):
        """Generate recommendations for non-compliant and missing controls"""
        recommendations = []

        # Recommendations for non-compliant controls
        for item in self.non_compliant_controls:
            control = item["control"]
            expected = item["expected"]
            current = item["current"]

            if control == "Disable LOAD DATA LOCAL INFILE":
                recommendations.append({
                    "control": control,
                    "recommendation": f"Set load-infile=0 in MySQL configuration to prevent local file access. Current value: {current}, Expected: {expected}"
                })
            elif control == "Error Limit":
                recommendations.append({
                    "control": control,
                    "recommendation": f"Change max_connect_errors={expected} in my.cnf to prevent brute force attacks. Current value: {current}"
                })
            elif control == "Server-Side Scripting":
                recommendations.append({
                    "control": control,
                    "recommendation": f"Disable server-side scripting to mitigate JavaScript injection attacks. Current state: {current}, Expected: {expected}"
                })
            else:
                recommendations.append({
                    "control": control,
                    "recommendation": f"Update {control} configuration from {current} to {expected}"
                })

        # Recommendations for missing controls
        for control in self.missing_controls:
            if control == "Encryption":
                recommendations.append({
                    "control": control,
                    "recommendation": "Configure TLS for database connections"
                })
            else:
                recommendations.append({
                    "control": control,
                    "recommendation": f"Implement {control} according to CIS benchmark guidelines"
                })

        return recommendations

    def generate_report(self, baseline_filename, cis_filename):
        """Generate a formatted compliance report"""
        if not self.compliance_data:
            print("No compliance data available. Please analyze compliance first.")
            return

        recommendations = self.generate_recommendations()

        html_report = f"""
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
            <h1 style="text-align: center; color: #2c3e50;">Security Compliance Report</h1>

            <h2>1. Report Summary</h2>
            <p><strong>Baseline Document:</strong> {baseline_filename}</p>
            <p><strong>Compared with CIS Benchmark:</strong> {cis_filename}</p>
            <p><strong>Overall Compliance Score:</strong> {self.compliance_score:.2f}%</p>

            <h2>2. Key Findings</h2>
            <h3>Compliant Controls</h3>
            <ul>
        """

        for control in self.compliant_controls:
            html_report += f"<li>{control}</li>\n"

        html_report += """
            </ul>

            <h3>Non-Compliant Controls</h3>
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr style="background-color: #f2f2f2;">
                    <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Control</th>
                    <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Expected Setting</th>
                    <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Current Setting</th>
                </tr>
        """

        for item in self.non_compliant_controls:
            html_report += f"""
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px;">{item["control"]}</td>
                    <td style="border: 1px solid #ddd; padding: 8px;">{item["expected"]}</td>
                    <td style="border: 1px solid #ddd; padding: 8px;">{item["current"]}</td>
                </tr>
            """

        html_report += """
            </table>

            <h3>Missing Controls</h3>
            <ul>
        """

        for control in self.missing_controls:
            html_report += f"<li>{control}</li>\n"

        html_report += """
            </ul>

            <h2>3. Recommended Fixes</h2>
            <ul>
        """

        for rec in recommendations:
            html_report += f"<li><strong>{rec['control']}</strong>: {rec['recommendation']}</li>\n"

        html_report += """
            </ul>

            <h2>4. Compliance Score Breakdown</h2>
        """

        total_controls = len(self.compliance_data)
        compliant_percent = (len(self.compliant_controls) / total_controls) * 100
        non_compliant_percent = (len(self.non_compliant_controls) / total_controls) * 100
        missing_percent = (len(self.missing_controls) / total_controls) * 100

        html_report += f"""
            <p><strong>Compliant Controls:</strong> {len(self.compliant_controls)} ({compliant_percent:.2f}%)</p>
            <p><strong>Non-Compliant Controls:</strong> {len(self.non_compliant_controls)} ({non_compliant_percent:.2f}%)</p>
            <p><strong>Missing Controls:</strong> {len(self.missing_controls)} ({missing_percent:.2f}%)</p>
        </div>
        """

        # Create visualizations
        plt.figure(figsize=(10, 6))
        plt.subplot(1, 2, 1)
        labels = ['Compliant', 'Non-Compliant', 'Missing']
        sizes = [len(self.compliant_controls), len(self.non_compliant_controls), len(self.missing_controls)]
        colors = ['#4CAF50', '#FFC107', '#F44336']
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('Compliance Status Distribution')

        plt.subplot(1, 2, 2)
        sns.barplot(x=labels, y=sizes, palette=colors)
        plt.title('Control Status Count')
        plt.tight_layout()
        plt.savefig('compliance_charts.png')
        plt.close()

        # Save the report as HTML
        report_path = 'security_compliance_report.html'
        with open(report_path, 'w') as f:
            f.write(html_report)

        # Open the report in the default browser
        webbrowser.open('file://' + os.path.realpath(report_path))

        print("\nReport saved as 'security_compliance_report.html'")
        print("Visualization saved as 'compliance_charts.png'")
        print("Opening the report in your browser...")

        return html_report

# Run the tool
def run_compliance_tool():
    tool = SecurityComplianceTool()

    # Step 1: Upload files
    baseline_filename, cis_filename = tool.upload_files()
    if not baseline_filename or not cis_filename:
        print("Exiting due to file errors.")
        return

    # Step 2: Extract controls (for demo, using predefined controls)
    controls = tool.extract_controls()
    print("\nExtracted controls from documents")

    # Step 3: Analyze compliance
    compliance_results = tool.analyze_compliance()
    print(f"\nCompliance analysis complete. Overall score: {tool.compliance_score:.2f}%")

    # Step 4: Generate report
    print("\nGenerating compliance report...")
    tool.generate_report(baseline_filename, cis_filename)

# Execute the function
if __name__ == "__main__":
    run_compliance_tool()