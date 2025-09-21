from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By

service = Service('msedgedriver.exe')
options = Options()
options.add_argument('--headless')
driver = webdriver.Edge(service=service, options=options)
driver.get('https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero=11001418902420250012300&SoloActivos=false&pagina=1')
body_text = driver.find_element(By.TAG_NAME, 'body').text
print(body_text)
driver.quit()