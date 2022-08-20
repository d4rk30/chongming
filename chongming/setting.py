import os
import sys
from chongming import app

WIN = sys.platform.startswith('win')
if WIN:  # 如果是 Windows 系统，使用三个斜线
    prefix = 'sqlite:///'
else:  # 否则使用四个斜线
    prefix = 'sqlite:////'

SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', prefix + os.path.join(os.path.dirname(app.root_path), 'data.db'))
SQLALCHEMY_TRACK_MODIFICATIONS = False  # 关闭对模型修改的监控
