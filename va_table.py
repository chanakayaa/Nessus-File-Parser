import xml.etree.ElementTree as ET
from collections import defaultdict
import os

#-----------------------------------------------------------------------------------------------------------------------------------------

## POWER ISN'T DETERMINED BY YOUR SIZE

        ##BUT BY THE SIZE OF YOUR HEART & DREAMS

                        # FUTURE PIRATE KING " MONKEY D. LUFFY " 

#-----------------------------------------------------------------------------------------------------------------------------------------



# Function to parse nesses file is defined here

def parse_nessus_file(file_path):
    vulnerabilities = defaultdict(list)

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            host_ip = report_host.get("name")

            for item in report_host.findall(".//ReportItem"):
                # Check if the "Risk Factor" indicates the vulnerability should be included
                risk_factor_element = item.find(".//risk_factor")
                if risk_factor_element is not None:
                    risk_factor = risk_factor_element.text.strip()  # Remove leading/trailing spaces
                else:
                    risk_factor = "N/A"  # Set a default value if the element is not found

                if risk_factor in ["Critical", "High", "Medium", "Low"]:
                    vulnerability_name = item.get("pluginName")
                    solution = item.find(".//solution").text.strip() if item.find(".//solution") is not None else "N/A"
                    
                    # Append the data for this vulnerability, including the IP address
                    vulnerabilities[vulnerability_name].append({
                        "Risk Factor": risk_factor,
                        "Solution": solution,
                        "IP Address (Port number)": f"{host_ip} ({item.get('port', '')})"
                    })

    except Exception as e:
        print("Error parsing Nessus file:", e)

    return vulnerabilities

# Function to generate html page is defined here

def generate_html_table(vulnerabilities):
    # Define a mapping of criticality levels to sort order and color codes
    criticality_info = {
        "Critical": {"order": 1, "color": "#C00000", "impact": "* * * * *"},
        "High": {"order": 2, "color": "#FF0000", "impact": "* * * *"},
        "Medium": {"order": 3, "color": "#ED7D31", "impact": "* * *"},
        "Low": {"order": 4, "color": "#70AD47", "impact": "* *"}
    }

    # Sort vulnerabilities by risk factor
    sorted_vulnerabilities = sorted(vulnerabilities.items(), key=lambda x: criticality_info.get(x[1][0]['Risk Factor'], {}).get('order', 5))

    # The HTML Headers are defined here
    table = "<div style='width: 6cm;'><table border='1' style='border-collapse: collapse; width: 50%; max-width: 6cm;'>\n"
    headers = [
        "<th style='text-align:center; background-color:#1F497D; color:white; font-family: Verdana; font-size: 15px; font-weight: bold;'>Vulnerability</th>",
        "<th style='text-align:center; background-color:#1F497D; color:white; font-family: Verdana; font-size: 15px; font-weight: bold;'>Criticality</th>",
        "<th style='text-align:center; background-color:#1F497D; color:white; font-family: Verdana; font-size: 15px; font-weight: bold;'>Impact on Business</th>",
        "<th style='text-align:center; background-color:#1F497D; color:white; font-family: Verdana; font-size: 15px; font-weight: bold;'>Recommendations</th>"
    ]
    table += "<tr>" + "".join(header for header in headers) + "</tr>\n"

    for vulnerability_name, vulnerability_list in sorted_vulnerabilities:
        # First row for Vulnerability, Criticality, Risk Factor, and Solution
        row = "<tr>"

        # Add Verdana font, bold style, left alignment, and font size 15px to "Vulnerability Name" column
        row += f"<td style='font-family: Verdana; font-weight: bold; text-align: left; font-size: 15px; padding-left: 0.5cm; padding-right: 0.5cm;'>{vulnerability_name}</td>"

        # Add color, Verdana font, bold style, medium center alignment, and font size 15px to "Criticality" column
        risk_factor = vulnerability_list[0]['Risk Factor']
        impact_color = criticality_info[risk_factor]['color']
        row += f"<td style='color:{impact_color}; font-family: Verdana; font-weight: bold; text-align: center; font-size: 15px; padding-left: 0.5cm; padding-right: 0.5cm;'>{criticality_info[risk_factor]['impact']}</td>"

        # Add color, Verdana font, bold style, medium center alignment, font size 15px, and 0.5 cm padding to the "Risk Factor" column
        # Add color, Verdana font, bold style, medium center alignment, font size 15px, and 0.5 cm padding to the "Risk Factor" column
        row += f"<td style='color:{impact_color}; font-family: Verdana; font-weight: bold; text-align: center; font-size: 15px; padding-left: 0.5cm; padding-right: 0.5cm;'>{risk_factor}</td>"

        # Add Verdana font, font size 15px, and 0.5 cm padding to the "Solution" column
        solution = vulnerability_list[0]['Solution']
        row += f"<td style='font-family: Verdana; font-size: 15px; padding-left: 0.5cm; padding-right: 0.5cm;'>{solution}</td>"

        row += "</tr>\n"
        table += row

        # Second row for IP Addresses with ports in the format "IP (Port No .:Port number)"
        row = "<tr>"

        ips_with_ports = set()  # Use a set to avoid duplicate ports
        for vuln in vulnerability_list:
            ip, port = vuln['IP Address (Port number)'].split(' (')
            port = port.rstrip(')')
            if port not in ["0", "N/A"]:
                ip_with_port = f"{ip} (Port No.: {port})"
                ips_with_ports.add(ip_with_port)
            else:
                ips_with_ports.add(ip)

        # Add a merged cell for IP Addresses with ports
        ips = ", ".join(ips_with_ports)
        row += f"<td colspan='4' style='font-family: Verdana; font-size: 15px; padding-left: 0.5cm;'>{ips}</td>"

        row += "</tr>\n"
        table += row

    table += "</table></div>"
    return table



   
### -------------------------------------CREATED BY :- PUSHKAR SINGH ------------------------------------------------------------------------

# ... (previous code)

if __name__ == "__main__":
    # "The One Piece Does Exist!" 
    print("\n********************************************")
    print("*                                          *")
    print("*       VULNERABILITY  PARSER              *")
    print("*                                          *")
    print("********************************************\n")

    # Prompt the user for the Nessus file location in the command prompt
    nessus_file_path = input("Enter the location of the Nessus file: ")

    # Check if the Nessus file path is provided and the file exists
    if nessus_file_path and os.path.exists(nessus_file_path):
        parsed_vulnerabilities = parse_nessus_file(nessus_file_path)

        html_table = generate_html_table(parsed_vulnerabilities)

        # Determine the directory of the Nessus file
        nessus_file_directory = os.path.dirname(nessus_file_path)

        # Create the path for the va_table.html file in the same directory
        html_file_path = os.path.join(nessus_file_directory, "va_table.html")



        with open(html_file_path, "w", encoding="utf-8") as output_file:
            output_file.write(html_table)

        print(f"GO CHECK YOUR FILE SYSTEM: {html_file_path}")

    else:
        print("\nA R A - A R A\nCheck the Nessus file path and try again.\n")



# ------------------------------------------------------Scars On The Back Are A Swordsman's Shame ------------------------------------------------
