Inštalácia základných nástrojov (Elasticsearch, Logstash, Kibana):

```
apt update
apt upgrade
apt install openjdk-11-jdk wget apt-transport-https curl gnupg2
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list
apt update
apt install elasticsearch
apt install logstash
apt install kibana
```

Úprava konfiguračného súboru pre Elasticsearch (/etc/elasticsearch/elasticsearch.yml):

```
network.host: <your-ip>
http.port: 9200
discovery.type: single-node
```

Zapneme službu elasticsearch a skontrolujeme či počúva na porte 9200:

```
systemctl start elasticsearch
systemctl enable elasticsearch
ss -antlp | grep 9200
curl -X GET http://<your-ip>:9200
```


Vytvoríme konfiguračný súbor pre Logstash (/etc/logstash/conf.d/logstash.conf):

```
input {
  beats {
    port => 5044
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGLINE}" }
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}


output {
  elasticsearch {
    hosts => ["<your-ip>:9200"]
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}
```

Spustíme logstash

```
systemctl start logstash.service
systemctl enable logstash.service
```

Úprava konfiguračného súboru pre Kibanu (/etc/kibana/kibana.yml):

```
server.host: "your-ip"
elasticsearch.hosts: ["http://<your-ip>:9200"]
```

Spustíme kibanu

```
systemctl start kibana.service
systemctl enable kibana.service
```

Nainštalujeme filebeat:
```
apt install filebeat
```

Úprava konfiguračného súboru pre Filebeat (/etc/filebeat/filebeat.yml):

```
Dashboards
	setup.dashboards.enabled: true
Kibana
	host: "your-ip:5601"
output.elasticsearch	
 	hosts: ["<your-ip>:9200"]
	index: "filebeat-%{+yyyy.MM.dd}"

nakoniec pridáme:
	setup.template.name: "filebeat"
	setup.template.pattern: "filebeat-*"
	setup.ilm.enabled: false
```	

Zapneme modul systém a spustíme inštaláciu:

```
filebeat modules enable system
filebeat setup -e
systemctl start filebeat
systemctl enable filebeat
```
 
```
apt install python3-pip 
git clone https://github.com/Yelp/elastalert.git
cd elastalert

pip3 install "setuptools>=11.3"
pip3 install pyOpenSSL

python3 setup.py install
pip3 install "elasticsearch>=5.0.0"
```

```
cp config.yaml.example config.yaml
```

Otvoríme konfiguračný súbor pre ElastAlert a nastavíme potrebné veci (elastalert/config.yaml): 

```
# This is the folder that contains the rule yaml files
# Any .yaml file will be loaded as a rule
rules_folder: example_rules

# How often ElastAlert will query Elasticsearch
# The unit can be anything from weeks to seconds
run_every:
 	  minutes: 1

# ElastAlert will buffer results from the most recent
# period of time, in case some log sources are not in real time
buffer_time:
  minutes: 15

# The Elasticsearch hostname for metadata writeback
# Note that every rule can have its own Elasticsearch host
es_host: <your-ip>

# The Elasticsearch port
es_port: 9200
```

Vytvoríme index:

```
elastalert-create-index
```


```
cd elastalert/example_rules/
mkdir my_rules
cd my_rules
```

Vytvoríme si nové pravidlo, vďaka ktorému sme schopní detegovať neúspešné prihlásenie cez SSH (ssh_failure.yaml)

```
name: ssh_failure
type: frequency
index: filebeat-*
num_events: 5
timeframe:
  hours: 1

filter:
- term:
   event.outcome: "failure"
- term:
   process.name: "sshd"
query_key: related.user

alert:
 - slack

slack_webhook_url: webhook-url 
slack_channel_override: "test"
slack_username_override: "@eva.markova"
```

Otestujeme a spustíme pravidlo:

```
elastalert-test-rule --config config.yaml example_rules/my_rules/ssh_failure.yaml
python3 -m elastalert.elastalert --verbose --rule example_rules/my_rules/ssh_failure.yaml
```

Inštalácia formátu Sigma:

```
pip3 install sigmatools
pip3 install "python-dateutil<2.7.0,>=2.6.0"
git clone https://github.com/Neo23x0/sigma.git
cd sigma/
```

Prezrieme si aj konvertér:
```
sigmac -l
sigmac -t elastalert -c winlogbeat rules/windows/sysmon/sysmon_config_modification.yml > /root/elastalert/example_rules/my_rules/elastalert_sysmon_config_modification.yml
```

Prezrieme si konfiguráky "winlogbeat" a pod.:

```
cd /sigma/tools/config
cat winlogbeat.yml
cat elk-defaultindex-filebeat.yml
```

Prezrieme si pravidlá, ktoré pre nás vytvorila komunita ľudí a na základe tohto pravidla vytvoríme vlastné:

```
cd sigma/rules/linux/auditd
cat lnx_auditd_create_account.yml
mkdir /root/sigma/rules/my_rules
cd sigma/rules/my_rules/
```

```
nano create_account.yml
```

```
title: Creation Of An User Account
references:
    - 'MITRE Attack technique T1136; Create Account '
logsource:
    product: linux
    service: auditd
detection:
    selection:
        process.name: 'useradd'
    condition: selection
falsepositives:
    - Admin activity
level: medium
tags:
    - attack.t1136    # an old one
    - attack.t1136.001
    - attack.persistence
```

Prekonvertujeme pravidlo:

```
sigmac -t elastalert -c elk-defaultindex-filebeat /root/sigma/rules/my_rules/create_account.yml > /root/elastalert/example_rules/my_rules/elastalert_create_account.yml
```

Získame: 

```
alert:
- debug
description: ''
filter:
- query:
    query_string:
      query: process.name:"useradd"
index: filebeat-*
name: Creation-Of-An-User-Account_0
priority: 3
realert:
  minutes: 0
type: any
```

Ale nesmieme zabudnúť pridať webhook url a typ alertu zmeniť z "debug" na "slack":

```
alert:
- slack
slack_webhook_url: webhook-url
slack_channel_override: "test"
slack_username_override: "@eva.markova"
```

Otestujeme a spustíme pravidlo:

```
elastalert-test-rule --config config.yaml example_rules/my_rules/elastalert_create_account.yml
python3 -m elastalert.elastalert --verbose --rule example_rules/my_rules/elastalert_create_account.yml
```
