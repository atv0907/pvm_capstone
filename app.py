from flask import Flask, render_template, request, redirect, url_for
from lxml import etree as ET
import os
from os.path import join, dirname, realpath
import sqlite3
import pip._vendor.requests
import json
import textwrap
import pandas as pd

#Track - 07-05-2022 (Test)

app = Flask(__name__)

con = sqlite3.connect("db.db")
print("DB Connection Established")

UPLOAD_FOLDER = 'static/files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def main():
    return render_template("index.html")

@app.route("/upload")
def upload():
    return render_template("upload.html")

@app.route("/upload", methods=['POST'])
def upload_file():
    inventory_file = request.files['file']
    if inventory_file.filename != '':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], inventory_file.filename)
        inventory_file.save(file_path)
        csv_data = pd.read_csv(file_path, usecols=["Name","Version"],skiprows=1)
        csv_data_list = csv_data.set_index('Name').T.to_dict('list')
        print(csv_data_list)
    return render_template("index.html")


@app.route("/search")
def form():
    return render_template('form.html')

@app.route("/search2")
def form2():
    return render_template('form.html')

@app.route("/search2", methods=['POST'])
def search2():
    class CPE_Search:
        def __init__(self, cpe_id):
            self.cpe_id = cpe_id

    #Command line argument Parse
    text = request.form['text']

    #Obtain vulnerability information corresponding to CPE from NVD in JSON format
    cpe_name = text
    api = 'https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword={cpe_name}'
    uri = api.format(cpe_name=cpe_name)
    response = pip._vendor.requests.get(uri)
    json_data = json.loads(response.text)
    cpes = json_data['result']['cpes']
    results=[]
    for item in cpes:
        jcpe_id = item['cpe23Uri'] # CVE-Get ID
        #jcpe_title = item['titles']['title']

        results.append(CPE_Search(jcpe_id))  
    return render_template("view4.html", results=results)


@app.route("/search", methods=['POST'])
def search():
    class CVE_Search:
        def __init__(self, cve_id, cwe_id, cvssv3, cvssv2, description):
            self.cve_id = cve_id
            self.cwe_id = cwe_id
            self.cvssv3 = cvssv3
            self.cvssv2 = cvssv2
            self.description = description

    #Command line argument Parse
    text = request.form['text']

    #Obtain vulnerability information corresponding to CPE from NVD in JSON format
    cpe_name = text
    api = 'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_name}'
    uri = api.format(cpe_name=cpe_name)
    response = pip._vendor.requests.get(uri)
    json_data = json.loads(response.text)
    vulnerabilities = json_data['result']['CVE_Items']
    results=[]
    for vuln in vulnerabilities:
        jcve_id = vuln['cve']['CVE_data_meta']['ID']  # CVE-Get ID
        jcurrent_description = vuln['cve']['description']['description_data'][0]['value']  #Get Current Description
        jcwe_id = vuln['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']  # CWE-Get ID

        #Get BaseScore and VectorString if you have CVSS v3 information
        if 'baseMetricV3' in vuln['impact']:
            jcvssv3_base_score = vuln['impact']['baseMetricV3']['cvssV3']['baseScore']
            cvssv3_vector_string = vuln['impact']['baseMetricV3']['cvssV3']['vectorString']
            
        else:
            jcvssv3_base_score = None
            cvssv3_vector_string = None

        #Get BaseScore and VectorString for CVSS v2
        jcvssv2_base_score = vuln['impact']['baseMetricV2']['cvssV2']['baseScore']
        cvssv2_vector_string = vuln['impact']['baseMetricV2']['cvssV2']['vectorString']

        #output
        x='---------'
        text = textwrap.dedent('''
        CVE-ID:{cve_id}<br>
        CWE-ID:{cwe_id}<br>
        CVSSv3 BaseScore:{cvssv3_base_score} CVSSv3 VectorString:{cvssv3_vector_string}<br>
        CVSSv2 BaseScore:{cvssv2_base_score} CVSSv2 VectorString: {cvssv2_vector_string}<br>
        Current Description:<br>
        {current_description}<br>
        ''')
        #z=text.format(cve_id=cve_id, cwe_id=cwe_id, cvssv3_base_score=cvssv3_base_score, cvssv3_vector_string=cvssv3_vector_string,
                          #cvssv2_base_score=cvssv2_base_score, cvssv2_vector_string=cvssv2_vector_string, current_description=current_description)
        y='---------'
        results.append(CVE_Search(jcve_id,jcwe_id,jcvssv3_base_score,jcvssv2_base_score,jcurrent_description))

    print(results[0].cve_id)    
    return render_template("view3.html", results=results)
    
    


@app.route("/view")
def view():
    con = sqlite3.connect("db.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    device_query = cur.execute("select * from Device").fetchall()
    soft_query = cur.execute("select softName, softVendor, softBuildVer from Software").fetchall()
    cpe_query = cur.execute("select cpeName, cpeNotes from CPE").fetchall()
    cve_query = cur.execute("select cveName, cveDescription, cvePublishDate, cvssScore from CVE").fetchall()
    return render_template("view.html", device_query=device_query, soft_query=soft_query, cpe_query=cpe_query, cve_query=cve_query)

@app.route('/view/<name>')
def test(name):
    con = sqlite3.connect("db.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    device_query = cur.execute("select * from Device where deviceName = ?", (name,)).fetchall()
    soft_query = cur.execute("select softName, softVendor, softBuildVer from Software where deviceName = ?", (name,)).fetchall()
    #cpe_query = cur.execute("SELECT CPE.cpeName, CPE.cpeNotes FROM CPE INNER JOIN Software ON CPE.softID=Software.softID WHERE Software.deviceName = ?", (name,)).fetchall()
    #cve_query = cur.execute("select cveName, cveDescription, cvePublishDate, cvssScore from CVE").fetchall()
    vuln_query = cur.execute("SELECT v.cveName, v.cveDescription, v.cvePublishDate, v.cvssScore, c.cpeName, c.cpeNotes FROM CVE v INNER JOIN CPE c ON v.cpeID=c.cpeID WHERE v.cpeID IN (SELECT cpeID FROM CPE INNER JOIN Software ON CPE.softID=Software.softID WHERE Software.deviceName = ?)", (name,)).fetchall()
    return render_template("view2.html", device_query=device_query, soft_query=soft_query, vuln_query=vuln_query)
    

if __name__ == "__main__":
    app.run()

