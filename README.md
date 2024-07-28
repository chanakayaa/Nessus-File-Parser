 Nessus File Parser and HTML Report Generator

 Description
This Python script parses a Nessus XML file and generates an HTML table summarizing the vulnerabilities found during the scan. The report includes details such as the vulnerability name, its criticality, the impact on the business, recommendations, and the affected assets (IP addresses and ports).

 Features
- Parses a Nessus XML file to extract vulnerabilities.
- Sorts vulnerabilities by severity: Critical, High, Medium, Low.
- Generates an HTML table summarizing the vulnerabilities.
- Displays the affected assets along with their respective ports.
- Provides color-coded severity levels for easy identification.

 Dependencies
- Python 3.x
- `xml.etree.ElementTree` (standard library)
- `collections.defaultdict` (standard library)
- `os` (standard library)

 Usage

 1. Prepare the Nessus XML File
Ensure you have the Nessus XML file you want to parse.

 2. Run the Script
Execute the script from the command line and provide the path to your Nessus XML file when prompted.

bash
python nessus_parser.py


 3. Enter the Nessus File Location
When prompted, enter the full path to your Nessus XML file.

plaintext
Enter the location of the Nessus file: /path/to/your/nessus_file.nessus


 4. Check the Output
After successful execution, the script generates an HTML file named `va_table.html` in the same directory as your Nessus XML file.


 Customization
Feel free to modify the script to fit your specific needs. You can adjust the HTML styles, add more details to the report, or integrate additional functionality as required.

 Credits
This script was created by Pushkar Singh. Inspired by the philosophy: "Power isn't determined by your size, but by the size of your heart and dreams" - Future Pirate King "Monkey D. Luffy".

---

For any questions or issues, please contact the creator. Happy parsing!
