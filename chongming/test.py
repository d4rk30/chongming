from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
import time

service = Service(executable_path="../chromedriver/chromedriver")
options = webdriver.ChromeOptions()
options.add_experimental_option('excludeSwitches', ['enable-automation'])  # 此步骤很重要，设置为开发者模式，防止被各大网站识别出来使用了Selenium
driver = webdriver.Chrome(service=service, options=options)
driver.wait = WebDriverWait(driver, 10)  # 超时时长为10s

script = '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
                '''
driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})

driver.get("https://www.cnvd.org.cn/shareData/list")  # 这次返回的是 521 相关的防爬js代码
# driver.get("https://www.cnvd.org.cn/")  # 调用2次 self.browser.get 解决 521 问题
time.sleep(10)
html = driver.page_source
print(html)
