from chongming import db
from datetime import datetime


class MetaCNVD(db.Model):
    __tablename__ = "meta_cnvd"
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    cnvd_id = db.Column(db.String(20))  # CNVD编号
    cve_id = db.Column(db.String(20))  # CVE编号
    cve_url = db.Column(db.String(250))
    name = db.Column(db.String(250))  # 漏洞名称
    level = db.Column(db.String(20))  # 漏洞危险等级
    vuln_category = db.Column(db.String(250))  # 漏洞类型
    submit_date = db.Column(db.String(250))  # 报送日期
    open_date = db.Column(db.String(250))  # 公开日期
    reference = db.Column(db.Text)  # 参考链接
    fix_method = db.Column(db.Text)  # 解决方案
    vuln_description = db.Column(db.Text)  # 漏洞描述
    patch_name = db.Column(db.Text)  # 补丁名称
    patch_description = db.Column(db.Text)  # 补丁描述


class MetaCNVDProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    product = db.Column(db.String(250))  # 产品名称
    cnvd_id = db.Column(db.String(20))  # CNVD编号


class MetaNVD(db.Model):
    __tablename__ = "meta_nvd"
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    cve_id = db.Column(db.String(20))  # CVE编号
    vuln_description = db.Column(db.Text)  # 漏洞描述
    cvss_v3_vector_string = db.Column(db.String(250))  # CVSS3矢量信息
    cvss_v3_attack_vector = db.Column(db.String(20))  # 攻击途径
    cvss_v3_attack_complexity = db.Column(db.String(20))  # 攻击复杂度
    cvss_v3_privileges_required = db.Column(db.String(20))  # 权限要求
    cvss_v3_user_interaction = db.Column(db.String(20))  # 用户交互
    cvss_v3_scope = db.Column(db.String(20))  # 影响范围
    cvss_v3_confidentiality_impact = db.Column(db.String(20))  # 机密性影响
    cvss_v3_integrity_impact = db.Column(db.String(20))  # 完整性影响
    cvss_v3_availability_impact = db.Column(db.String(20))  # 可用性影响
    cvss_v3_base_score = db.Column(db.Float)  # 基础分数
    cvss_v3_base_severity = db.Column(db.String(20))  # 漏洞危险等级
    cvss_v3_exploitability_score = db.Column(db.Float)  # 可利用性分数
    cvss_v3_impact_score = db.Column(db.Float)  # 影响分
    cvss_v2_vector_string = db.Column(db.String(250))  # CVSS2矢量信息
    cvss_v2_access_vector = db.Column(db.String(20))  # 访问途径
    cvss_v2_access_complexity = db.Column(db.String(20))  # 访问难度
    cvss_v2_authentication = db.Column(db.String(20))  # 身份验证
    cvss_v2_confidentiality_impact = db.Column(db.String(20))  # 机密性影响
    cvss_v2_integrity_impact = db.Column(db.String(20))  # 完整性影响
    cvss_v2_availability_impact = db.Column(db.String(20))  # 可用性影响
    cvss_v2_base_score = db.Column(db.Float)  # 基础分
    cvss_v2_severity = db.Column(db.String(20))  # 漏洞危险等级
    cvss_v2_exploitability_score = db.Column(db.Float)  # 可利用性得分
    cvss_v2_impact_score = db.Column(db.Float)  # 影响得分
    cvss_v2_ac_insuf_info = db.Column(db.Boolean)
    cvss_v2_obtain_all_privilege = db.Column(db.Boolean)  # 获得所有特权
    cvss_v2_obtain_user_privilege = db.Column(db.Boolean)  # 获得用户权限
    cvss_v2_obtain_other_privilege = db.Column(db.Boolean)  # 获得其他权限
    cvss_v2_user_interaction_required = db.Column(db.Boolean)  # 需要用户交付行为
    cpe = db.Column(db.JSON)  # CPE信息
    published_date = db.Column(db.String(250))  # 公开日期
    last_modified_date = db.Column(db.String(250))  # 最后更新日期


class MetaNVDCWE(db.Model):
    __tablename__ = "meta_nvd_cwe"
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    cwe_id = db.Column(db.String(20))  # CWE编号
    cve_id = db.Column(db.String(20))  # CVE编号


class MetaNVDReference(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    name = db.Column(db.Text)  # 参考链接
    url = db.Column(db.Text)  # 参考链接
    refsource = db.Column(db.String(250))  # 来源
    tags = db.Column(db.JSON)  # 标签
    cve_id = db.Column(db.String(20))  # CVE编号


# NVD原始数据
class MetaNVDJSONData(db.Model):
    __tablename__ = "meta_nvd_json_data"
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    json_data = db.Column(db.Text)


class MetaCNNVD(db.Model):
    __tablename__ = "meta_cnnvd"
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    name = db.Column(db.String(250))  # 漏洞名称
    cnnvd_id = db.Column(db.String(20))  # CNNVD编号
    published = db.Column(db.String(250))  # 公开日期
    modified = db.Column(db.String(250))  # 最后更新日期
    source = db.Column(db.String(250))  # 漏洞发布单位
    severity = db.Column(db.String(20))  # 漏洞危险等级
    vuln_type = db.Column(db.String(100))  # 漏洞类型
    thrtype = db.Column(db.String(100))  # 威胁类型
    vuln_descript = db.Column(db.Text)  # 漏洞描述
    vulnerable_configuration = db.Column(db.Text)  # 影响实体描述
    vuln_software_list = db.Column(db.Text)  # 影响产品描述
    cve_id = db.Column(db.String(20))  # CVE编号
    vuln_solution = db.Column(db.Text)  # 补丁信息


class MeatCNNVDReference(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    cnnvd_id = db.Column(db.String(20))  # CNNVD编号
    ref_source = db.Column(db.String(20))  # 参考链接来源
    ref_name = db.Column(db.String(250))  # 参考链接名称
    ref_url = db.Column(db.Text)  # 参考链接地址


class ErrorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    create_time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间
    update_time = db.Column(db.DateTime, default=datetime.utcnow)  # 更新时间
    log_source = db.Column(db.String(250))  # 日志来源
    log_details = db.Column(db.Text)  # 日志记录
