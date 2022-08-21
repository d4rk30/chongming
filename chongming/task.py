from chongming import db
from chongming.models import MetaNVD, MetaNVDJSONData, MetaNVDReference, MetaNVDCWE, MetaCNVD, MetaCNVDProduct
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

scheduler = BackgroundScheduler()


class NVDControlKits(object):
    def __init__(self, data):
        self.data = data

    def analysis(self):
        for item in self.data:
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')  # CVE编号
            try:
                vuln_description = item['cve']['description']['description_data'][0]['value']  # 漏洞描述
            except LookupError as e:
                vuln_description = None
            cvss_v3_vector_string = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'vectorString')  # CVSS3矢量信息
            cvss_v3_attack_vector = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'attackVector')  # 攻击途径
            cvss_v3_attack_complexity = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'attackComplexity')  # 攻击复杂度
            cvss_v3_privileges_required = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'privilegesRequired')  # 权限要求
            cvss_v3_user_interaction = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'userInteraction')  # 用户交互
            cvss_v3_scope = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('scope')  # 影响范围
            cvss_v3_confidentiality_impact = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'confidentialityImpact')  # 机密性影响
            cvss_v3_integrity_impact = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'integrityImpact')  # 完整性影响
            cvss_v3_availability_impact = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'availabilityImpact')  # 可用性影响
            cvss_v3_base_score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'baseScore')  # 基础分数
            cvss_v3_base_severity = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'baseSeverity')  # 漏洞危险等级
            cvss_v3_exploitability_score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'exploitabilityScore')  # 可利用性分数
            cvss_v3_impact_score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get(
                'impactScore')  # 影响分
            cvss_v2_vector_string = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'vectorString')  # CVSS2矢量信息
            cvss_v2_access_vector = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'accessVector')  # 访问途径
            cvss_v2_access_complexity = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'accessComplexity')  # 访问难度
            cvss_v2_authentication = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'authentication')  # 身份验证
            cvss_v2_confidentiality_impact = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'confidentialityImpact')  # 机密性影响
            cvss_v2_integrity_impact = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'integrityImpact')  # 完整性影响
            cvss_v2_availability_impact = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'availabilityImpact')  # 可用性影响
            cvss_v2_base_score = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get(
                'baseScore')  # 基础分
            cvss_v2_severity = item.get('impact', {}).get('baseMetricV2', {}).get('severity')  # 漏洞危险等级
            cvss_v2_exploitability_score = item.get('impact', {}).get('baseMetricV2', {}).get(
                'exploitabilityScore')  # 可利用性得分
            cvss_v2_impact_score = item.get('impact', {}).get('baseMetricV2', {}).get('impactScore')  # 影响得分
            cvss_v2_ac_insuf_info = item.get('impact', {}).get('baseMetricV2', {}).get('acInsufInfo')
            cvss_v2_obtain_all_privilege = item.get('impact', {}).get('baseMetricV2', {}).get(
                'obtainAllPrivilege')  # 获得所有特权
            cvss_v2_obtain_user_privilege = item.get('impact', {}).get('baseMetricV2', {}).get(
                'obtainUserPrivilege')  # 获得用户权限
            cvss_v2_obtain_other_privilege = item.get('impact', {}).get('baseMetricV2', {}).get(
                'obtainOtherPrivilege')  # 获得其他权限
            cvss_v2_user_interaction_required = item.get('impact', {}).get('baseMetricV2', {}).get(
                'userInteractionRequired')  # 需要用户交互行为
            cpe = item.get('configurations', {}).get('nodes')  # CPE信息
            published_date = item.get('publishedDate')  # 公开日期
            last_modified_date = item.get('lastModifiedDate')  # 最后更新日期
            meta_nvd = MetaNVD(cve_id=cve_id, vuln_description=vuln_description,
                               cvss_v3_vector_string=cvss_v3_vector_string, cvss_v3_attack_vector=cvss_v3_attack_vector,
                               cvss_v3_attack_complexity=cvss_v3_attack_complexity,
                               cvss_v3_privileges_required=cvss_v3_privileges_required,
                               cvss_v3_user_interaction=cvss_v3_user_interaction, cvss_v3_scope=cvss_v3_scope,
                               cvss_v3_confidentiality_impact=cvss_v3_confidentiality_impact,
                               cvss_v3_integrity_impact=cvss_v3_integrity_impact,
                               cvss_v3_availability_impact=cvss_v3_availability_impact,
                               cvss_v3_base_score=cvss_v3_base_score, cvss_v3_base_severity=cvss_v3_base_severity,
                               cvss_v3_exploitability_score=cvss_v3_exploitability_score,
                               cvss_v3_impact_score=cvss_v3_impact_score, cvss_v2_vector_string=cvss_v2_vector_string,
                               cvss_v2_access_vector=cvss_v2_access_vector,
                               cvss_v2_access_complexity=cvss_v2_access_complexity,
                               cvss_v2_authentication=cvss_v2_authentication,
                               cvss_v2_confidentiality_impact=cvss_v2_confidentiality_impact,
                               cvss_v2_integrity_impact=cvss_v2_integrity_impact,
                               cvss_v2_availability_impact=cvss_v2_availability_impact,
                               cvss_v2_base_score=cvss_v2_base_score, cvss_v2_severity=cvss_v2_severity,
                               cvss_v2_exploitability_score=cvss_v2_exploitability_score,
                               cvss_v2_impact_score=cvss_v2_impact_score, cvss_v2_ac_insuf_info=cvss_v2_ac_insuf_info,
                               cvss_v2_obtain_all_privilege=cvss_v2_obtain_all_privilege,
                               cvss_v2_obtain_user_privilege=cvss_v2_obtain_user_privilege,
                               cvss_v2_obtain_other_privilege=cvss_v2_obtain_other_privilege,
                               cvss_v2_user_interaction_required=cvss_v2_user_interaction_required, cpe=json.dumps(cpe),
                               published_date=published_date, last_modified_date=last_modified_date)
            db.session.add(meta_nvd)
            db.session.commit()
            print("解析基本数据完成")
            # 解析参考链接
            if len(item['cve']['references']['reference_data']) != 0:
                for reference in item['cve']['references']['reference_data']:
                    reference_url = reference.get('url')
                    reference_name = reference.get('name')
                    reference_refsource = reference.get('refsource')
                    reference_tags = reference.get('tags')
                    meta_nvd_reference = MetaNVDReference(name=reference_name, url=reference_url,
                                                          refsource=reference_refsource, tags=reference_tags,
                                                          cve_id=cve_id)
                    db.session.add(meta_nvd_reference)
                    db.session.commit
                    print("解析参考链接完成")
            # 解析CWE
            if len(item['cve']['problemtype']['problemtype_data'][0]['description']) != 0:
                for cwe in item['cve']['problemtype']['problemtype_data'][0]['description']:
                    print(cwe)
                    cwe_id = cwe.get('value')
                    print(cwe_id)
                    meta_nvd_cwe = MetaNVDCWE(cwe_id=cwe_id, cve_id=cve_id)
                    db.session.add(meta_nvd_cwe)
                    db.session.commit
                    print("解析cwe完成")
        print("完成一次")


# 获取NVD的官方接口数据，每小时一次，记录在Meat表中
def job1_get_nvd_data():
    # 获取请求数据
    api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    modStartDate = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%dT%H") + ":00:00:000 UTC%2B08:00"
    modEndDate = datetime.now().strftime("%Y-%m-%dT%H") + ":00:00:000 UTC%2B08:00"
    nvd_url = api_url + "?modStartDate=" + modStartDate + "&modEndDate=" + modEndDate + "&apiKey=2523e1c5-e126-4ece-b350-93109aba9573"
    rs = requests.get(nvd_url)
    # 记录原始api的json数据
    json_data = MetaNVDJSONData(json_data=rs.text)
    db.session.add(json_data)
    db.session.commit()
    # 处理数据
    if len(rs.json()['result']['CVE_Items']) == 0:
        # 当前时间段漏洞数据没有
        pass
    else:
        nvd_control_kits = NVDControlKits(data=rs.json()['result']['CVE_Items'])
        nvd_control_kits.analysis()


def get_cnvd_text(bs4xml):
    if bs4xml is not None:
        return bs4xml.get_text()
    else:
        return None


# 获取CNVD的数据，解析xml数据，每周一次，记录在Meta表中
def job2_get_cnvd_data():
    # download_xml_url = ""
    # rs = requests.get(download_xml_url)
    soup = BeautifulSoup(open("meta/cnvd/2022-08-08_2022-08-14.xml"), "xml")
    # 解析cnvd基本信息
    for bs_xml in soup.find_all('vulnerability'):
        cnvd_id = get_cnvd_text(bs_xml.number)
        cve_id = get_cnvd_text(bs_xml.cveNumber)
        cve_url = get_cnvd_text(bs_xml.cveUrl)
        name = get_cnvd_text(bs_xml.title)
        level = get_cnvd_text(bs_xml.serverity)
        vuln_category = get_cnvd_text(bs_xml.isEvent)
        submit_date = get_cnvd_text(bs_xml.submitTime)
        open_date = get_cnvd_text(bs_xml.openTime)
        reference = get_cnvd_text(bs_xml.referenceLink)
        fix_method = get_cnvd_text(bs_xml.formalWay)
        vuln_description = get_cnvd_text(bs_xml.description)
        patch_name = get_cnvd_text(bs_xml.patchName)
        patch_description = get_cnvd_text(bs_xml.patchDescription)
        meta_cnvd = MetaCNVD(cnvd_id=cnvd_id, cve_id=cve_id, cve_url=cve_url, name=name, level=level,
                             vuln_category=vuln_category, submit_date=submit_date, open_date=open_date,
                             reference=reference, fix_method=fix_method, vuln_description=vuln_description,
                             patch_name=patch_name, patch_description=patch_description)
        db.session.add(meta_cnvd)
        db.session.commit()
        # 解析CNVD产品信息
        for item in bs_xml.products:
            product = get_cnvd_text(item)
            meta_cnvd_product = MetaCNVDProduct(product=product, cnvd_id=cnvd_id)
            db.session.add(meta_cnvd_product)
            db.session.commit()
    print("任务完成")


# 每小时运行一次
scheduler.add_job(
    job2_get_cnvd_data,
    trigger='interval',
    seconds=10
)

scheduler.start()
