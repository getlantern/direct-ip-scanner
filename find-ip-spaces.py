#!/usr/bin/env python

import os
import sys
import subprocess
import re
from jinja2 import Template


def resolve_ips(domain):
    lines = subprocess.check_output(['host', domain]).strip().split('\n')
    return map(lambda l: l.split(' ')[-1], lines)

def find_autonomous_systems_for_ip(ip):
    output = subprocess.check_output(['whois', '-h', 'whois.radb.net', ip])
    return map(lambda o: re.search("AS\d*", o).group(), re.findall('origin:.*AS.*', output))

def check_autonomous_system(a):
    output = subprocess.check_output(['whois', '-h', 'whois.radb.net', a])
    for n in map(lambda e: e.split(' ')[-1], re.findall('as-name:.*', output)):
        print "Autonomous System %s belongs to: %s" % (a,n)

def get_autonomous_system_IPv4_ranges(a):
    output = subprocess.check_output(['whois', '-h', 'whois.radb.net', '--', '-i origin -T', 'route', a])
    return [n for n in map(lambda e: e.split(' ')[-1], re.findall('route:.*', output))]

def get_autonomous_system_IPv6_ranges(a):
    output = subprocess.check_output(['whois', '-h', 'whois.radb.net', '--', '-i origin -T', 'route6', a])
    return [n for n in map(lambda e: e.split(' ')[-1], re.findall('route6:.*', output))]


yaml_template = Template(
"""ipranges:
  - domain:
      name: r3---sn-bvvbax4pcxg-50ne.googlevideo.com
      url: 'https://r3---sn-bvvbax4pcxg-50ne.googlevideo.com/videoplayback?gir=yes&clen=69060963&keepalive=yes&pfa=5&mime=video%2Fwebm&itag=244&key=cms1&lmt=1449588821521369&signature=498721B0CC7FA2FB780E83003F29C0ECCEA552DC.0C969BF2089D1121BF8051DB9F8CAA074FA9FB9B&sparams=clen,ctier,dur,ei,expire,gir,hightc,id,initcwndbps,ip,ipbits,ipbypass,itag,keepalive,lmt,mime,mip,mm,mn,ms,mv,pcm2cms,pfa,pl,requiressl,source&ipbits=0&expire=1504336687&ctier=A&pl=44&id=o-AEo6vRIakwTI4a1RYXrhJS6GF56S93B06Q-Z4TlPqmqL&requiressl=yes&dur=714.280&ip=104.131.186.35&hightc=yes&source=youtube&ei=zwaqWYXFE-na8gT-34yoBw&alr=yes&ratebypass=yes&cpn=OkNWCw91Gruhdx0s&c=web&cver=html5&redirect_counter=1&cms_redirect=yes&ipbypass=yes&mip=2605:a601:41f3:e600:b0c7:60ea:d72f:468a&mm=31&mn=sn-bvvbax4pcxg-50ne&ms=au&mt=1504315004&mv=m&pcm2cms=yes&range=1909920-3743595&rn=11&rbuf=17766'
      response:
        sanvalue: *.googlevideo.com
        statuscode: 200
        headers:
          Server: gvs 1.0
      ranges:
      {% for ip in google_ip_ranges %}- {{ip}}
      {% endfor %}
"""
)

domain = 'www.google.com'

def render_template(ips):
    return yaml_template.render(google_ip_ranges=ips)

if __name__ == '__main__':
    ips = resolve_ips(domain)
    asys = set(find_autonomous_systems_for_ip(ips[0]))
    asys |= set(find_autonomous_systems_for_ip(ips[1]))

    for a in asys:
        check_autonomous_system(a)
        ip_ranges = get_autonomous_system_IPv6_ranges(a)
        ip_ranges = ip_ranges + get_autonomous_system_IPv4_ranges(a)
        yaml_str = render_template(ip_ranges)
        with open('./config.yaml', 'w+') as f:
            f.seek(0)
            read_data = f.write(yaml_str)
            f.truncate()
