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
      name: r4---sn-h5q7dnee.googlevideo.com
      url: 'https://r4---sn-h5q7dnee.googlevideo.com/videoplayback?sparams=clen%2Cdur%2Cei%2Cgir%2Cid%2Cinitcwndbps%2Cip%2Cipbits%2Citag%2Ckeepalive%2Clmt%2Cmime%2Cmm%2Cmn%2Cms%2Cmv%2Cpl%2Crequiressl%2Csource%2Cexpire&requiressl=yes&source=youtube&lmt=1504637021894817&dur=2237.721&clen=42187299&gir=yes&initcwndbps=1365000&expire=1504736535&ei=tyCwWY_6E9btcpvctqAB&itag=251&key=yt6&mime=audio%2Fwebm&mv=m&mt=1504714848&ms=au&pl=18&keepalive=yes&id=o-AMSt_0uyFpK1teNOP83xAjtmg5BbviwxK-xv6pj8r-aQ&ipbits=0&mn=sn-h5q7dnee&mm=31&ip=144.178.133.52&alr=yes&ratebypass=yes&signature=1891E58D2DD98CA0346F15A5518E063BFF31FDFD.B77B4E8F52A8F67CBA4BE99C5B4835E773B5B2B4&cpn=khT2WdxdNRM_IlNT&c=web&cver=html5&range=576789-958139&rn=8&rbuf=25282'
      response:
        sanvalue: r4---sn-h5q7dnee.googlevideo.com
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
        ip_ranges = get_autonomous_system_IPv4_ranges(a)
        ip_ranges = ip_ranges + get_autonomous_system_IPv6_ranges(a)
        yaml_str = render_template(ip_ranges)
        with open('./config.yaml', 'w+') as f:
            f.seek(0)
            read_data = f.write(yaml_str)
            f.truncate()
