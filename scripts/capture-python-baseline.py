"""Capture legacy analysis outputs for development parity; never called by the native app."""
import importlib.util,json
from pathlib import Path
import pandas as pd
root=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name,root/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
engine=load('engine');cli=load('cli_parser');fixtures=root/'FirewallReview.Tests/Fixtures';fixtures.mkdir(parents=True,exist_ok=True)
pa={'Name':'low','Source Zone':'trust','Source Address':'192.0.2.1','Destination Zone':'untrust','Destination Address':'198.51.100.1','Application':'ssl','Service':'tcp-443','URL Category':'business','Action':'allow','Profile':'Configured','Options':'Log Forwarding Profile setting','Tags':'Configured','Rule Usage Hit Count':'10','NIST Documented':'Yes'}
palo=[pa|{'Name':'broad','Source Address':'192.0.2.0/24'},pa|{'Name':'admin','Service':'ssh'},pa|{'Name':'cleartext','Service':'http'},pa|{'Name':'zero','Rule Usage Hit Count':'0'},pa|{'Name':'reverse-unused','Source Address':'198.51.100.1','Destination Address':'192.0.2.1','Rule Usage Hit Count':'unused'},pa|{'Name':'disabled_Disabled'},pa|{'Name':'permissive','Source Address':'any','Destination Address':'any','Application':'any','URL Category':'any','Service':'any','Profile':'none','Tags':'none','Options':'none','NIST Documented':'No'},pa|{'Name':'unknown-object','Source Address':'branch-object'}]
ft={'Name':'low','Policy':'1','Status':'enabled','From':'lan','Source':'192.0.2.1','To':'wan','Destination':'198.51.100.1','Service':'HTTPS','Action':'ACCEPT','Security Profiles':'deep-inspection','Log':'all','Hit Count':'10'}
forti=[ft,ft|{'Name':'high','Policy':'2','Source':'all','Destination':'all','Service':'ALL','Security Profiles':''},ft|{'Name':'stale','Policy':'3','Hit Count':'0'},ft|{'Name':'disabled','Policy':'4','Status':'disabled'},ft|{'Name':'deny','Policy':'5','Action':'DENY','Source':'all','Destination':'all'},ft|{'Name':'no-log','Policy':'6','Log':'utm'}]
for name,rows,process in [('palo',palo,engine.process_palo_alto_rules),('forti',forti,engine.process_fortinet_rules)]:
 df=pd.DataFrame(rows);df.to_csv(fixtures/(name+'.csv'),index=False);result=process(df,'Synthetic Site')
 (fixtures/(name+'-expected.json')).write_text(json.dumps({'metrics':result['metrics'],'tables':{key:[str(row.get('Name',row.get('Policy',''))) for row in frame.to_dict('records')] for key,frame in result.items() if hasattr(frame,'to_dict')}},indent=2))
raw='''sw-version: 11.1.4
config {
 mgt-config {
  authentication {
   idle-timeout 5;
  }
  login-banner "Authorized use only";
  password-complexity {
   enabled yes;
   minimum-length 14;
  }
 }
 interface-management-profile {
  secured {
   ssh yes;
   permitted-ip {
    192.0.2.1/32;
   }
  }
 }
 zone {
  untrust {
   network-profile {
    zone-protection-profile protection;
   }
  }
 }
 rulebase {
  security {
   rules {
    "web-access" {
     from trust;
     to untrust;
     source 192.0.2.1;
     destination 198.51.100.1;
     application ssl;
     service tcp-443;
     category business;
     action allow;
     description "Approved business access";
     profile-setting {
      group security;
     }
    }
    "default-deny" {
     source any;
     destination any;
     action deny;
    }
   }
  }
 }
}
web-access vsys1 10 - - -
default-deny vsys1 100 - - -
'''
(fixtures/'panos.txt').write_text(raw)
df,nist,cis=cli.PaloAltoCLIParser(raw).parse();result=engine.process_palo_alto_rules(df,'Synthetic',nist,cis)
(fixtures/'panos-expected.json').write_text(json.dumps({'rows':df.to_dict('records'),'metrics':result['metrics'],'nist':nist,'cis':cis},indent=2))
print('Captured Palo Alto, Fortinet and PAN-OS CLI baselines.')
