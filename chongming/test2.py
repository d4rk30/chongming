from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service

FLAG = '/html/body/div[4]/div/form/div/p[5]/a/span'

url = "https://www.cnvd.org.cn/user/login"


def cdp_get(url, browser):
    try:
        browser.get(url)
        _ = WebDriverWait(browser, timeout).until(ec.presence_of_element_located((By.XPATH, FLAG)))
        return browser.page_source
    except Exception as e:
        with open("error.txt", "a+") as f:
            f.write(url + "\n")
        return ""


timeout = 10
options = webdriver.ChromeOptions()
options.add_experimental_option('excludeSwitches', ['enable-automation'])
service = Service(executable_path="../chromedriver/chromedriver")
browser = webdriver.Chrome(service=service, options=options)

script = '''
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        })
        '''
browser.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})

html = cdp_get(url, browser)
print(html)
