from bs4 import BeautifulSoup

a = []
soup = BeautifulSoup(open("../meta/cnvd/2022-08-08_2022-08-14.xml"), "xml")

print(len(soup.find_all('number')))
