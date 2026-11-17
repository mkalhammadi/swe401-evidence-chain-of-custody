import re, json, hashlib, os, sqlite3
from playwright.sync_api import sync_playwright
B="http://127.0.0.1:5055"; OUT="/home/claude/e2e/"
res={}
def login(page,u,pw="Demo@12345"):
    page.goto(B+"/login"); page.fill("#username",u); page.fill("#password",pw); page.click("form button"); page.wait_for_load_state()
def logout(page): page.click("text=Sign out"); page.wait_for_load_state()
with sync_playwright() as p:
    br=p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx=br.new_context(viewport={"width":1366,"height":800}, accept_downloads=True)
    page=ctx.new_page()
    # E2E-01 admin creates a user
    login(page,"admin"); page.goto(B+"/admin/users")
    page.fill("input[name=username]","noura"); page.fill("input[name=full_name]","Noura Investigator")
    page.fill("input[name=email]","noura@coc.local"); page.fill("input[name=password]","Strong#Pass2026")
    page.select_option("form select[name=role] >> nth=-1","Investigator"); page.click("text=Create user"); page.wait_for_load_state()
    res["E2E-01"]= "User noura created." in page.content(); page.screenshot(path=OUT+"e2e01_user_created.png"); logout(page)
    # E2E-02 investigator uploads via UI; hash shown equals sha256sum
    login(page,"investigator"); page.goto(B+"/cases/1")
    page.set_input_files("input[type=file]", OUT+"laptop_triage_notes.txt")
    page.fill("textarea[name=description]","Notes from on-site triage"); page.click("text=Upload and hash"); page.wait_for_load_state()
    shown=page.inner_text("td.hash").strip(); expected=open(OUT+"expected.txt").read().split()[0]
    res["E2E-02"]= (shown==expected, shown, expected); page.screenshot(path=OUT+"e2e02_upload_hash.png", full_page=False)
    ev_url=page.url
    # E2E-03 transfer request then accept
    page.select_option("select[name=to_user_id]", label="Layla Investigator (Investigator)")
    page.fill("input[name=reason]","Needs malware analysis"); page.click("text=Request"); page.wait_for_load_state()
    pending="Transfer pending to Layla Investigator" in page.content(); logout(page)
    login(page,"investigator2"); page.goto(B+"/transfers/")
    row=page.locator("tr", has_text="Needs malware analysis"); row.locator("input[name=note]").fill("Received for analysis"); row.locator("button[value=accept]").click(); page.wait_for_load_state()
    page.goto(ev_url); cust="Layla Investigator" in page.inner_text("table >> nth=0")
    res["E2E-03"]=(pending and cust); page.screenshot(path=OUT+"e2e03_transfer_accepted.png", full_page=True)
    # E2E-04 tamper with stored file then verify in UI
    con=sqlite3.connect("/tmp/demo/coc.db"); sf=con.execute("select stored_filename from evidence where original_filename='laptop_triage_notes.txt'").fetchone()[0]; con.close()
    path="/tmp/demo/store/"+sf; os.chmod(path,0o640); open(path,"ab").write(b"x")
    page.click("text=Verify integrity"); page.wait_for_load_state()
    res["E2E-04"]= "INTEGRITY FAILURE" in page.content() and "Mismatch" in page.content(); page.screenshot(path=OUT+"e2e04_tamper_detected.png"); logout(page)
    # E2E-05 audit chain intact, then edit a row directly and verify again
    login(page,"auditor"); page.goto(B+"/audit"); page.click("text=Verify whole chain"); page.wait_for_load_state()
    ok1="Audit chain intact" in page.content(); page.screenshot(path=OUT+"e2e05a_chain_ok.png")
    con=sqlite3.connect("/tmp/demo/coc.db"); rid=con.execute("select id from custody_events where action='UPLOAD' order by id limit 1").fetchone()[0]
    con.execute("update custody_events set details=details||' (edited)' where id=?", (rid,)); con.commit()
    page.click("text=Verify whole chain"); page.wait_for_load_state()
    broken=f"BROKEN at entry #{rid}" in page.content(); page.screenshot(path=OUT+"e2e05b_chain_broken.png")
    con.execute("update custody_events set details=replace(details,' (edited)','') where id=?", (rid,)); con.commit(); con.close()
    res["E2E-05"]=(ok1 and broken, rid)
    # E2E-06 auditor exports pdf
    page.goto(ev_url)
    with page.expect_download() as d: page.click("text=Export PDF report")
    d.value.save_as(OUT+"e2e06_report.pdf"); res["E2E-06"]=open(OUT+"e2e06_report.pdf","rb").read(4)==b"%PDF"
    br.close()
print(json.dumps(res, indent=1))
json.dump(res, open(OUT+"e2e_results.json","w"), indent=1)
