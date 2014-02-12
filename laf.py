#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# author: takeshix@adversec.com
import requests,argparse,sys

parser = argparse.ArgumentParser(description='Find admin/login panel for a single host (-d) or a list of hosts (-l).')
parser.add_argument('-d', metavar='host', help='host to scan')
parser.add_argument('-l', metavar='hostfile|-', type=argparse.FileType('r'), help='list of hosts, one per line (- instead of a file to read from stdin)')
parser.add_argument('-sys', metavar='system', help='comma seperated list of dirs|php|cfm|asp|html|pma (default: dirs)')
parser.add_argument('-c', metavar='cookie', help='cookie string for authenticated scanning')
parser.add_argument('-ic', action='store_true', default=False, help='ignore invalid tls certificate')
parser.add_argument('-k', action='store_true', default=False, help='halt on first valid path')
parser.add_argument('-v', action='store_true', default=False, help='enable verbosity')
args = parser.parse_args()

if not args.d and not args.l:
    print 'either host or hostfile must be supplied.'
    sys.exit(0)

class mylogs:
    def fail(self,msg,sc):
        print '\033[1;31m[FAILED] [STATUS: {}] {}\033[0m'.format(sc,msg)

    def info(self,msg,sc): 
        print '\033[1;32m[VALID] [STATUS: {}] {}\033[0m'.format(sc,msg)

if args.v: log = mylogs()
        
asp = [
'account.asp','admin/account.asp','admin/index.asp','admin/login.asp',
'admin/admin.asp','admin_area/admin.asp','admin_area/login.asp','admin_area/index.asp',
'bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp','admin/home.asp',
'admin/controlpanel.asp','admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp',
'admin-login.asp','admin/cp.asp','cp.asp','administrator/account.asp','administrator.asp',
'login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','administrator/login.asp',
'moderator/admin.asp','controlpanel.asp','user.asp','admincp/index.asp','admincp/login.asp',
'admincontrol.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp',
'webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp',
'panel-administracion/login.asp','adminLogin.asp','admin/adminLogin.asp','home.asp','admin.asp',
'adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','panel-administracion/index.asp',
'panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp',
'administrator/index.asp','admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp',
'admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp','adm.asp','affiliate.asp',
'adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp',
'siteadmin/index.asp','Util/login.aspx'
]

cfm = [
'account.cfm','admin/account.cfm','admin/index.cfm','admin/login.cfm',
'admin/admin.cfm','admin_area/admin.cfm','admin_area/login.cfm','admin_area/index.cfm',
'bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm',
'admin/controlpanel.cfm','admin.cfm','pages/admin/admin-login.cfm','admin/admin-login.cfm',
'admin-login.cfm','admin/cp.cfm','cp.cfm','administrator/account.cfm','administrator.cfm',
'login.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm',
'administrator/login.cfm','moderator/admin.cfm','controlpanel.cfm',
'user.cfm','admincp/index.cfm','admincp/login.cfm','admincontrol.cfm','admin/account.cfm',
'adminpanel.cfm','webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','webadmin/login.cfm',
'admin/admin_login.cfm','admin_login.cfm','panel-administracion/login.cfm','adminLogin.cfm',
'admin/adminLogin.cfm','home.cfm','admin.cfm','adminarea/index.cfm','adminarea/admin.cfm',
'adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm',
'modelsearch/index.cfm','modelsearch/admin.cfm','administrator/index.cfm',
'admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm',
'admin2/login.cfm','admin2/index.cfm','adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm',
'memberadmin.cfm','administratorlogin.cfm','siteadmin/login.cfm','siteadmin/index.cfm'
]

php = [
'admin/account.php','admin/index.php','admin/fuckoff.php','admin/login.php',
'admin/admin.php','admin/account.php','admin_area/admin.php','admin_area/login.php',
'siteadmin/login.php','siteadmin/index.php','admin_area/index.php','bb-admin/index.php',
'bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin/controlpanel.php',
'admin.php','admin/cp.php','cp.php','administrator/index.php','administrator/login.php',
'nsw/admin/login.php','index.php?page=admin','webadmin/login.php','admin/admin_login.php',
'admin_login.php','administrator/account.php','administrator.php','pages/admin/admin-login.php',
'admin/admin-login.php','admin-login.php','login.php','modelsearch/login.php',
'moderator.php','moderator/login.php','moderator/admin.php','account.php',
'controlpanel.php','admincontrol.php','rcjakar/admin/login.php','webadmin.php',
'webadmin/index.php','webadmin/admin.php','adminpanel.php','user.php',
'panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php',
'home.php','admin.php','adminarea/index.php','adminarea/admin.php','adminarea/login.php',
'panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php',
'modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php',
'admin2.php','admin2/login.php','admin2/index.php','adm/index.php','adm.php',
'affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','server_login.php/',
'user_login.php','userlogin.php','fileadmin.php','ur-admin.php','typo3/login.php'
]

html = [
'account.html','controlpanel.html','admincontrol.html','moderator/login.html',
'admin_login.html','panel-administracion/login.html','bb-admin/index.html',
'admin_area/admin.html','admin_area/login.html','admin_area/index.html',
'bb-admin/login.html','bb-admin/admin.html','admin/home.html',
'admin/controlpanel.html','admin.html','admin/cp.html','cp.html',
'administrator/index.html','administrator/login.html','administrator/account.html',
'administrator.html','login.html','modelsearch/login.html','moderator.html',
'adm/index.html','adm.html','moderator/admin.html','panel-administracion/index.html',
'panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admin/admin_login.html','admincontrol/login.html','adm/index.html','adm.html',
'admin/account.html','adminpanel.html','webadmin.html','pages/admin/admin-login.html',
'admin/admin-login.html','webadmin/index.html','webadmin/admin.html',
'webadmin/login.html','user.html','admincp/index.html','admin/adminLogin.html',
'adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html',
'adminarea/login.html','admin-login.html','siteadmin/login.html','admin/index.html',
'admin/login.html','admin/admin.html','admincontrol/login.html'
]

dirs = [
'admin/',
'administrator/',
'administration/',
'moderator/',
'webadmin/',
'mobileadmin/',
'adminarea/',
'bb-admin/',
'typo3/',
'typo3admin/',
'typo3login/',
'wp-admin/',
'wp-login/',
'pma/',
'PMA/',
'dbadmin/',
'adminLogin/',
'admin_area/',
'cmsadmin/',
'fileadmin/',
'vmailadmin/',
'acp/',
'acp2/',
'cp/',
'login/',
'login2/',
'xtAdmin/',
'mysql/',
'controlpanel/',
'panel-administracion/',
'instadmin/',
'memberadmin/',
'sshadmin/',
'staradmin/',
'webadministrator/',
'SysAdmin/',
'sysadmin/',
'IndyAdmin/',
'administratie/',
'dir-login/',
'database-admin/',
'logon-sysadmin/',
'myadmin/',
'private/',
'power-user/',
'power_user/',
'sysadmins/',
'AdminTools/',
'admin1/',
'formslogin/',
'globes_admin/',
'newsadmin/',
'simplelogin/',
'sqladmin/',
'sqladministration/',
'sql-admin/',
'administratorlogin/',
'adm/',
'vadmind/',
'wizmysqladmin/',
'v2/painel/',
'utility_login/',
'UserLogin/',
'useradmin/',
'ur-admin/',
'system-administration/',
'SysAdmin/',
'SysAdmin2/',
'sys-admin/',
'support-login/',
'Super-Admin/',
'sub-login/',
'startadmin/',
'sshadmin/',
'ss_vms_admin_sm/',
'smblogin/',
'simpleLogin/',
'showlogin/',
'ServerAdministrator/',
'server_admin_small/',
'rcLogin/',
'radmind/',
'radmind-1/',
'pureadmin/',
'project-admins/',
'platz_login/',
'phpSQLiteAdmin/',
'phppgadmin/',
'phpldapadmin/',
'pgadmin/',
'painel/',
'openvpnadmin/',
'navSiteAdmin/',
'myadmin/',
'meta_login/',
'memlogin/',
'manuallogin/',
'maintenance/',
'macadmin/',
'Lotus_Domino_Admin/',
'logo_sysadmin/',
'loginflat/',
'login1/',
'LiveUser_Admin/',
'irc-macadmin/',
'globes_admin/',
'ezsqliteadmin/',
'directadmin/',
'dir-login/',
'database_administration/',
'Database_Administration/',
'cpanel_file/',
'customer_login/',
'cmsadmin/',
'ccms/',
'cadmins/',
'bigadmin/',
'bbadmin/',
'autologin/',
'adminisztrátora/',
'administrivia/',
'administratie/',
'administracion/',
'administraçao/',
'administracao/',
'administr8/',
'administer/',
'admin4_colon/',
'admin4_account/',
]

pma = [
'phpmyadmin/',
'phpmyAdmin/',
'phpMyAdmin/',
'phpMyAdmin2/',
'phpMyAdmin3/',
'phpMyAdmin4/',
'php-my-admin/',
'sqlmanager/',
'p/m/a/',
'PMA2005/',
'pma2005/',
'phpmanager/',
'php-myadmin/',
'phpmy-admin/',
'sqlweb/',
'websql/',
'webdb/',
'mysqladmin/',
'mysql-admin/',
'phpmyadmin2/',
'phpmyadmin3/',
'phpmyadmin4/',
'phpMyAdmin2/',
'phpMyAdmin3/',
'phpMyAdmin4/',
'phpMyAdmin-2/',
'phpMyAdmin-3/',
'phpMyAdmin-4/',
'php-my-admin/',
'phpMyAdmin-4.1.7-english/',
'phpMyAdmin-4.1.7-all-languages/',
'phpMyAdmin-4.1.7-english/',
'phpMyAdmin-4.1.7-all-languages/',
'phpMyAdmin-4.1.6-english/',
'phpMyAdmin-4.1.6-all-languages/',
'phpMyAdmin-4.1.5-english/',
'phpMyAdmin-4.1.5-all-languages/',
'phpMyAdmin-4.1.4-english/',
'phpMyAdmin-4.1.4-all-languages/',
'phpMyAdmin-4.1.3-english/',
'phpMyAdmin-4.1.3-all-languages/',
'phpMyAdmin-4.1.2-english/',
'phpMyAdmin-4.1.2-all-languages/',
'phpMyAdmin-4.1.1-english/',
'phpMyAdmin-4.1.1-all-languages/',
'phpMyAdmin-4.1.0-english/',
'phpMyAdmin-4.1.0-all-languages/',
'phpMyAdmin-4.0.10-english/',
'phpMyAdmin-4.0.10-all-languages/',
'phpMyAdmin-4.0.9-english/',
'phpMyAdmin-4.0.9-all-languages/',
'phpMyAdmin-4.0.8-english/',
'phpMyAdmin-4.0.8-all-languages/',
'phpMyAdmin-4.0.7-english/',
'phpMyAdmin-4.0.7-all-languages/',
'phpMyAdmin-4.0.6-english/',
'phpMyAdmin-4.0.6-all-languages/',
'phpMyAdmin-4.0.5-english/',
'phpMyAdmin-4.0.5-all-languages/',
'phpMyAdmin-4.0.4.2-english/',
'phpMyAdmin-4.0.4.2-all-languages/',
'phpMyAdmin-4.0.4.1-english/',
'phpMyAdmin-4.0.4.1-all-languages/',
'phpMyAdmin-4.0.4-english/',
'phpMyAdmin-4.0.4-all-languages/',
'phpMyAdmin-4.0.3-english/',
'phpMyAdmin-4.0.3-all-languages/',
'phpMyAdmin-4.0.2-english/',
'phpMyAdmin-4.0.2-all-languages/',
'phpMyAdmin-4.0.1-english/',
'phpMyAdmin-4.0.1-all-languages/',
'phpMyAdmin-4.0.0-english/',
'phpMyAdmin-4.0.0-all-languages/',
'phpMyAdmin-3.5.8.2-english/',
'phpMyAdmin-3.5.8.2-all-languages/',
'phpMyAdmin-3.5.8.1-english/',
'phpMyAdmin-3.5.8.1-all-languages/',
'phpMyAdmin-3.5.6-english/',
'phpMyAdmin-3.5.6-all-languages/',
'phpMyAdmin-3.5.5-english/',
'phpMyAdmin-3.5.5-all-languages/',
'phpMyAdmin-3.5.4-english/',
'phpMyAdmin-3.5.4-all-languages/',
'phpMyAdmin-3.5.2.2-english/',
'phpMyAdmin-3.5.2.2-all-languages/',
'phpMyAdmin-3.5.2.1-english/',
'phpMyAdmin-3.5.2.1-all-languages/',
'phpMyAdmin-3.5.2-english/',
'phpMyAdmin-3.5.2-all-languages/',
'phpMyAdmin-3.5.1-english/',
'phpMyAdmin-3.5.1-all-languages/',
'phpMyAdmin-3.5.0-english/',
'phpMyAdmin-3.5.0-all-languages/',
'phpMyAdmin-3.4.11.1-english/',
'phpMyAdmin-3.4.11.1-all-languages/',
'phpMyAdmin-3.4.11-english/',
'phpMyAdmin-3.4.11-all-languages/',
'phpMyAdmin-3.4.10.2-english/',
'phpMyAdmin-3.4.10.2-all-languages/',
'phpMyAdmin-3.4.10.1-english/',
'phpMyAdmin-3.4.10.1-all-languages/',
'phpMyAdmin-3.4.10-english/',
'phpMyAdmin-3.4.10-all-languages/',
'phpMyAdmin-3.4.9-english/',
'phpMyAdmin-3.4.9-all-languages/',
'phpMyAdmin-3.4.8-english/',
'phpMyAdmin-3.4.8-all-languages/',
'phpMyAdmin-3.4.7.1-english/',
'phpMyAdmin-3.4.7.1-all-languages/',
'phpMyAdmin-3.4.7-english/',
'phpMyAdmin-3.4.7-all-languages/',
'phpMyAdmin-3.4.6-english/',
'phpMyAdmin-3.4.6-all-languages/',
'phpMyAdmin-3.4.5-english/',
'phpMyAdmin-3.4.5-all-languages/',
'phpMyAdmin-3.4.4-english/',
'phpMyAdmin-3.4.4-all-languages/',
'phpMyAdmin-3.4.3.2-english/',
'phpMyAdmin-3.4.3.2-all-languages/',
'phpMyAdmin-3.4.3.1-english/',
'phpMyAdmin-3.4.3.1-all-languages/',
'phpMyAdmin-3.4.3-english/',
'phpMyAdmin-3.4.3-all-languages/',
'phpMyAdmin-3.4.2-english/',
'phpMyAdmin-3.4.2-all-languages/',
'phpMyAdmin-3.4.1-english/',
'phpMyAdmin-3.4.1-all-languages/',
'phpMyAdmin-3.4.0-english/',
'phpMyAdmin-3.4.0-all-languages/',
'phpMyAdmin-3.3.10.5-english/',
'phpMyAdmin-3.3.10.5-all-languages/',
'phpMyAdmin-3.3.10.4-english/',
'phpMyAdmin-3.3.10.4-all-languages/',
'phpMyAdmin-3.3.10.3-english/',
'phpMyAdmin-3.3.10.3-all-languages/',
'phpMyAdmin-3.3.10.2-english/',
'phpMyAdmin-3.3.10.2-all-languages/',
'phpMyAdmin-3.3.10.1-english/',
'phpMyAdmin-3.3.10.1-all-languages/',
'phpMyAdmin-3.3.10-english/',
'phpMyAdmin-3.3.10-all-languages/',
'phpMyAdmin-3.3.9.2-english/',
'phpMyAdmin-3.3.9.2-all-languages/',
'phpMyAdmin-3.3.9.1-english/',
'phpMyAdmin-3.3.9.1-all-languages/',
'phpMyAdmin-3.3.9-english/',
'phpMyAdmin-3.3.9-all-languages/',
'phpMyAdmin-3.3.8.1-english/',
'phpMyAdmin-3.3.8.1-all-languages/',
'phpMyAdmin-3.3.8-english/',
'phpMyAdmin-3.3.8-all-languages/',
'phpMyAdmin-3.3.7-english/',
'phpMyAdmin-3.3.7-all-languages/',
'phpMyAdmin-3.3.6-english/',
'phpMyAdmin-3.3.6-all-languages/',
'phpMyAdmin-3.3.5.1-english/',
'phpMyAdmin-3.3.5.1-all-languages/',
'phpMyAdmin-3.3.5.0-english/',
'phpMyAdmin-3.3.5.0-all-languages/',
'phpMyAdmin-3.3.4.0-english/',
'phpMyAdmin-3.3.4.0-all-languages/',
'phpMyAdmin-3.3.3.0-english/',
'phpMyAdmin-3.3.3.0-all-languages/',
'phpMyAdmin-3.3.2.0-english/',
'phpMyAdmin-3.3.2.0-all-languages/',
'phpMyAdmin-3.3.1.0-english/',
'phpMyAdmin-3.3.1.0-all-languages/',
'phpMyAdmin-3.3.0-english/',
'phpMyAdmin-3.3.0-all-languages/',
'phpMyAdmin-3.2.5.0-english/',
'phpMyAdmin-3.2.5.0-all-languages/',
'phpMyAdmin-3.2.4.0-english/',
'phpMyAdmin-3.2.4.0-all-languages/',
'phpMyAdmin-3.2.3.0-english/',
'phpMyAdmin-3.2.3.0-all-languages/',
'phpMyAdmin-3.2.2.1-english/',
'phpMyAdmin-3.2.2.1-all-languages/',
'phpMyAdmin-3.2.2.0-english/',
'phpMyAdmin-3.2.2.0-all-languages/',
'phpMyAdmin-3.2.1.0-english/',
'phpMyAdmin-3.2.1.0-all-languages/',
'phpMyAdmin-3.2.0.1-english/',
'phpMyAdmin-3.2.0.1-all-languages/',
'phpMyAdmin-3.2.0-english/',
'phpMyAdmin-3.2.0-all-languages/',
'phpMyAdmin-3.1.5-english/',
'phpMyAdmin-3.1.5-all-languages/',
'phpMyAdmin-3.1.4-rc2-english/',
'phpMyAdmin-3.1.4-rc2-all-languages/',
'phpMyAdmin-3.1.4-rc1-english/',
'phpMyAdmin-3.1.4-rc1-all-languages/',
'phpMyAdmin-3.1.4-english/',
'phpMyAdmin-3.1.4-all-languages/',
'phpMyAdmin-3.1.3.2-english/',
'phpMyAdmin-3.1.3.2-all-languages/',
'phpMyAdmin-3.1.3.1-english/',
'phpMyAdmin-3.1.3.1-all-languages/',
'phpMyAdmin-3.1.3-english/',
'phpMyAdmin-3.1.3-all-languages/',
'phpMyAdmin-3.1.2-english/',
'phpMyAdmin-3.1.2-all-languages/',
'phpMyAdmin-3.1.1-english/',
'phpMyAdmin-3.1.1-all-languages/',
'phpMyAdmin-3.1.0-english/',
'phpMyAdmin-3.1.0-all-languages/',
'phpMyAdmin-3.0.1.1-english/',
'phpMyAdmin-3.0.1.1-all-languages/',
'phpMyAdmin-3.0.1-english/',
'phpMyAdmin-3.0.1-all-languages/',
'phpMyAdmin-3.0.0-rc1-english/',
'phpMyAdmin-3.0.0-rc1-all-languages/',
'phpMyAdmin-3.0.0-english/',
'phpMyAdmin-3.0.0-beta-english/',
'phpMyAdmin-3.0.0-beta-all-languages/',
'phpMyAdmin-3.0.0-alpha-english/',
'phpMyAdmin-3.0.0-alpha-all-languages/',
'phpMyAdmin-3.0.0-all-languages/',
'phpMyAdmin-2.11.11.3-english/',
'phpMyAdmin-2.11.11.3-all-languages/',
'phpMyAdmin-2.11.11.2-english/',
'phpMyAdmin-2.11.11.2-all-languages/',
'phpMyAdmin-2.11.11.1-english/',
'phpMyAdmin-2.11.11.1-all-languages/',
'phpMyAdmin-2.11.11-english/',
'phpMyAdmin-2.11.11-all-languages/',
'phpMyAdmin-2.11.10.1-english/',
'phpMyAdmin-2.11.10.1-all-languages/',
'phpMyAdmin-2.8.2/',
'phpMyAdmin-2.8.1/',
'phpMyAdmin-2.8.1-rc1/',
'phpMyAdmin-2.8.0/',
'phpMyAdmin-2.8.0.4/',
'phpMyAdmin-2.8.0.3/',
'phpMyAdmin-2.8.0.2/',
'phpMyAdmin-2.8.0.1/',
'phpMyAdmin-2.8.0-rc2/',
'phpMyAdmin-2.8.0-rc1/',
'phpMyAdmin-2.8.0-beta1/',
'phpMyAdmin-2.7.0/',
'phpMyAdmin-2.7.0-rc1/',
'phpMyAdmin-2.7.0-pl2/',
'phpMyAdmin-2.7.0-pl1/',
'phpMyAdmin-2.7.0-beta1/',
'phpMyAdmin-2.6.4/',
'phpMyAdmin-2.6.4-rc1/',
'phpMyAdmin-2.6.4-pl4/',
'phpMyAdmin-2.6.4-pl3/',
'phpMyAdmin-2.6.4-pl2/',
'phpMyAdmin-2.6.4-pl1/',
'phpMyAdmin-2.6.3/',
'phpMyAdmin-2.6.3-rc1/',
'phpMyAdmin-2.6.3-pl1/',
'phpMyAdmin-2.6.2/',
'phpMyAdmin-2.6.2-rc1/',
'phpMyAdmin-2.6.2-pl1/',
'phpMyAdmin-2.6.2-beta1/',
'phpMyAdmin-2.6.1/',
'phpMyAdmin-2.6.1-rc2/',
'phpMyAdmin-2.6.1-rc1/',
'phpMyAdmin-2.6.1-pl3/',
'phpMyAdmin-2.6.1-pl2/',
'phpMyAdmin-2.6.1-pl1/',
'phpMyAdmin-2.6.0/',
'phpMyAdmin-2.6.0-rc3/',
'phpMyAdmin-2.6.0-rc2/',
'phpMyAdmin-2.6.0-rc1/',
'phpMyAdmin-2.6.0-pl3/',
'phpMyAdmin-2.6.0-pl2/',
'phpMyAdmin-2.6.0-pl1/',
'phpMyAdmin-2.6.0-beta2/',
'phpMyAdmin-2.6.0-beta1/',
'phpMyAdmin-2.6.0-alpha/',
'phpMyAdmin-2.6.0-alpha2/',
'phpMyAdmin-2.5.7/',
'phpMyAdmin-2.5.7-pl1/',
'phpMyAdmin-2.5.6/',
'phpMyAdmin-2.5.6-rc2/',
'phpMyAdmin-2.5.6-rc1/',
'phpMyAdmin-2.5.5/',
'phpMyAdmin-2.5.5-rc2/',
'phpMyAdmin-2.5.5-rc1/',
'phpMyAdmin-2.5.5-pl1/',
'phpMyAdmin-2.5.4/',
'phpMyAdmin-2.5.1/',
'phpMyAdmin-2.2.6/',
'phpMyAdmin-2.2.3/',
'phpMyAdmin-2.1.0/',
'phpMyAdmin-2.0.5/',
'phpMyAdmin-1.3.0/',
'phpMyAdmin-1.1.0/',
]

global_payloads = {'asp':asp,'cfm':cfm,'php':php,'html':html,'dirs':dirs,'pma':pma}

success_strings = [
    'username',
    'user',
    'password',
    'pass',
    'kennwort',
    'benutzername',
    'login',
    'logon'
    'clave',
    'admin',
    'panel'
    'authorization',
    'authenticate',
    'root',
    'configure',
    'Client Authentication Remote Service',
    'ExtendNet DX Configuration',
    'forcelogon.htm',
    'IMail Server Web Messaging',
    'Management Console',
    'console',
    'Please identify yourself',
    'identify',
    'Reload acp_userinfo database',
    'RSA SecurID User Name Request',
    'The userid or password that was specified is not valid.',
    'TYPE=password'
    ]

failed_strings = [
    'Access Failed',
    'an error',
    'Bad Request',
    'could not find',
    'error has occurred',
    'Error 404',
    'Error Occurred While Processing Request',
    'Error processing SSI file',
    'FireWall-1 message',
    'name=qt id="search" size=40 value=" "',
    'No web site is configured at this address',
    'not found',
    'parameter is incorrect',
    'Unable to complete your request',
    'unable to open',
    'Hack Attempts',
    'does not exist',
    '<b>Wrong URL.',
    'page may no longer exist',
    'page no longer exist',
    'Your session has expired',
    'no longer available',
    'konnte nicht gefunden werden'
    ]

def gen_payload():
    pl = []
    try:
        if not args.sys:
            pl = pl + dirs
        else:
            for pset in args.sys.split(','):
                pl = pl + global_payloads[pset]
    
        return pl
    except Exception as e:
        print str(e)

def check(pl,host):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0'
    }

    if args.c:
        cookies = dict(args.c)
    else:
        cookies = None
    
    try:
        if args.ic:
            return requests.get('{}{}'.format(host,pl), headers=headers, cookies=cookies, verify=False)
        else:
            return requests.get('{}{}'.format(host,pl), headers=headers, cookies=cookies)

    except Exception as e:
        print str(e)

if __name__ == '__main__':
    hosts = []
    try:
        pl = gen_payload()
        if args.d:
            hosts.append(args.d)
        else:
            hosts = hosts + args.l.read().split('\n')
    
        for host in hosts:
            if not host: continue

            if not host.startswith('http://') and not host.startswith('https://'):
                host = 'http://{}'.format(host)

            if not host.endswith('/'):
                host = '{}/'.format(host)

            for payload in pl:
                valid = False
                ret = check(payload, host)
                sc = ret.status_code
                co = ret.text.upper()

                if sc == 200:
                    for s in success_strings:
                        if s in co:
                            valid = True
                            break

                    for s in failed_strings:
                        if s in co:
                            valid = False
                            break

                if valid or sc == 401:
                    if args.v: log.info('{}{}'.format(host,payload),sc)
                    else: print '{}{}'.format(host,payload)
                    if args.k: sys.exit(0)
                elif not valid or sc != 200:
                    if args.v: log.fail('{}{}'.format(host,payload),sc)

    except Exception as e:
        print str(e)            
            


