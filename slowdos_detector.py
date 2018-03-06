#!/usr/bin/python
#
# SlowDoS_Detector - detects Slow HTTP DoS attacks on pcap files - currently Slow GET and Slow POST
# Author: Ismael Goncalves - https://sharingsec.blogspot.com
#
# Usage: slowdos_dectector.py -f <mypcap.pcap> -s <myserverip>
#
# High-level description:
#
#   It opens the pcap file and use tshark to verify how many TCP sessions for the serverip it has
#   Once this is identified, if there is any session, it still uses tshark to break the pcap into small pcaps per TCP stream
#   Files are save to /tmp/sess-????.pcap and a mapping session file is created (/tmp/sessions.txt)
#   Once breaking of the pcap is done, it iterates all over small pcaps files identifying all slow transcations
#   A slow transcation here is considered the ones with no response from webservers in 25 seconds
#   The data are consolidated into a dictionary and a sample of the payload along with statistics are collected
#
# Pre-requisites: Linux, Python 2.7, tshark, scapy module for Python
#
#
# TO-DO
# - Implement verbosity for the output
# - Currently it supports only HTTP Clear text - add support for HTTPS (SSLKEYLOGFILE)  
# - Implement thread on breaking pcap to speed up process - this is taking too long - A MUST for large PCAPS!
# -    The ideia is to split the list of sessions into small lists, iterate over them and call a specialized split_pcap function
# - Implement a nice table reporting about the attack and graphs
# - Creation of a temp folder instead of using /tmp/
# - Save results to a CVS file or similar
# - Implement MAX number of concurrent connections results
# - Grab and display additional data such as non-offending requests from offending-ip (like probes) and detects TCP RESET from server
# - Detect Slow Read
# - Make it platform agnostic


import os
import argparse
try:
        from scapy.all import *
except:
        print('Error importing Scapy module')
        quit()

# define a time for a slow transaction
slow_t = 25

# store the results 
slow_sessions = { }

def parse_args():

    # Parsing CLI arguments
    sample = "Sample: python slowdos_detector.py -f file.pcap -s server-ip"
    parser = argparse.ArgumentParser(description='''SlowDos_Detector - Detects Slow HTTP DoS Attacks on pcap files
    Written by: Ismael Goncalves - https://sharingsec.blogspot.com''', prog="slowdos_detect", epilog=sample,formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-f", "--file", help="File containing the pcap to be analyzed", required=True) 
    parser.add_argument("-s", "--server", help="IP address of the targeted server" , required=True)
    parser.add_argument("-p", "--print_sessions", help="Print details of offending TCP sessions", action="store_true" )
    args = parser.parse_args()
    return args


def read_sessions(file,server_ip):

    sessions = rdpcap(file)
    amount_packets = len(sessions)
    s_time = sessions[0].time
    f_time = sessions[amount_packets - 1].time
    d_time = f_time - s_time

    maligno = 1
    total_time = 0
    bytes_sent = 0
    total_push = 0
    previous_push_t = 0
    total_time = 0
    sample_payload = ''
    client_ip = sessions[0].getlayer(IP).src
    source_port = sessions[0].getlayer(TCP).sport
    flow_id = file[10:14].lstrip('0')
    # stream 0 ?
    if flow_id=='':
       flow_id='0'

    for p in sessions:
        if p.getlayer(IP).src == server_ip:
           flags = p.getlayer(TCP).sprintf('%TCP.flags%')
           # check for a server response
	   # if the server responds faster than slow_t we conside a legitimate flow
           if flags == 'PA':
              if (p.time - s_time) < slow_t:
                 maligno = 0
                 break
        else:
           flags = p.getlayer(TCP).sprintf('%TCP.flags%')

	# check if it is a PA to compute bytes sent only by somebody else other than the server itsefl
        # do calculations for bytes sent and amount of flows
        if flags == 'PA' and p.getlayer(IP).src != server_ip:
	    # grab a sample payload from the first PA from the attacker
            if sample_payload=='':
               sample_payload = p.getlayer(TCP).payload.load
            if previous_push_t != 0:
               total_time = total_time + p.time - previous_push_t
            previous_push_t = p.time
            total_push = total_push + 1
            bytes_sent = bytes_sent + len(p.getlayer(TCP).payload)

    # if not identified the TCP session as malicious, skip it 
    if not maligno or bytes_sent == 0:
       return

    bytes_avg = bytes_sent / total_push
    req_avg_t = total_time / total_push

    sess = { "flow_id":flow_id,"t_bytes_sent" : bytes_sent, "bytes_avg": bytes_avg, "avg_interval": req_avg_t,"start_time":time.gmtime(s_time),
             "end_time": time.gmtime(f_time) , "sample_payload":sample_payload ,"source_port":source_port  }


    if client_ip in slow_sessions:
       slow_sessions[client_ip].append(sess)
    else:
       slow_sessions.update({client_ip:[sess]})


def split_pcap(main_pcap,server_ip,port="80"):

    files = []

    # find amount of sessions
    # replace this by process.subcall for safety calls and proper stdout treatment
    cmd ='tshark -r ' + main_pcap + ' -T fields -e tcp.stream -Y "tcp.port==' + port + ' and ip.dst==' + server_ip + '" |sort -n|uniq > /tmp/sessions.txt ' 
    print cmd
    os.system(cmd)

    streams = open('/tmp/sessions.txt').read().split()

    print 'Total number of TCP Sessions: ' + str(len(streams))

    for s in streams:
       s_file = '/tmp/sess-' + s.zfill(4) + '.pcap'
       os.system('tshark -r ' + main_pcap + ' -e tcp.stream -T fields -R "tcp.stream==' + s + '" -2 -w ' + s_file +' > /dev/null ')
       files.append(s_file)

    return files


def print_slow_transactions():

    for k in slow_sessions:
       print 'Report for Offending IP: ' + k + '\n'
       for l in slow_sessions.get(k):
          print l
          print "\n"

def display_summary(files):

    times = []
    avg_int = 0
    avg_bytes = 0
    total_bytes =0
    n_sessions = 0
    start_time = 0
    sessions = []

    if len(slow_sessions)==0:
       print 'No attack was identified'
       return

    for k in slow_sessions:
       for l in slow_sessions.get(k):
          n_sessions = n_sessions + 1
          avg_int = avg_int + l.get('avg_interval')
          avg_bytes = avg_bytes + l.get('bytes_avg')
          times.append(l.get('end_time'))
          if start_time == 0:
             start_time = l.get('start_time')

    print "Offending IP: " + k
    print "Number of Sessions: " + str(n_sessions)
    print "Request Average Interval: %.2f seconds" % (avg_int / n_sessions)
    print "Bytes Average per Request: " + str(avg_bytes / n_sessions)
    print "Attack Start Time: " + time.strftime('%Y-%m-%d - %H:%M:%S GMT', start_time)
    end_time = max(times)
    print "Attack End Time: " + time.strftime('%Y-%m-%d - %H:%M:%S GMT', end_time)
    print "Duration of the Attack: " + str( time.mktime(end_time) - time.mktime(start_time) ) + " seconds"

def clean_up(files):

    for f in files:
       os.remove(f)
    os.remove('/tmp/sessions.txt')


if __name__ == "__main__":
    args = parse_args()
    files = split_pcap(args.file,args.server)

    if len(files) == 0:
       print "No sessions were found in the pcap informed, please, review IP address of the server"
    for f in files:
       read_sessions(f,args.server)

    if args.print_sessions:
       print_slow_transactions()

    print "\n--------------- SUMMMARY ----------------\n"

    display_summary(files)

    clean_up(files)

