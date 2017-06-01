import iptc
import sys
import os
import subprocess
import re
import netaddr
import time

class TwoWayStatelessFirewall:
    def __init__(self):
        pass

    def run(self, args):
        prog = args[0]
        if len(args) < 2:
            self.usage(prog)
            return 1

        command = args[1]
        if command == "start":
            self.start(args)
        elif command == "stop":
            self.stop()
        else:
            self.usage(prog)
            return 1
        return 0

    def start(self, args):
        """Start the firewall."""
        for i in range(2,len(args)):
            if args[i] == "inputDrop" or args[i] == "inputAccept" or args[i] == "outputDrop" or args[i] == "outputAccept":
                self.ICMPRule(args[i])
                break
            elif args[i] == "blockFacebook" or args[i] == "unblockFacebook":
                self.facebookRule(args[i])
                break
            elif args[i] == "blockConnFromMAC" or args[i] == "unBlockConnFromMAC" or args[i] == "blockConnToMAC" or args[i] == "unBlockConnToMAC":
                self.macRule(args[i], args[i+1])
                break
            elif args[i] == "blockOutputPort" or args[i] == "unblockOutputPort":
                self.portRule(args[i],args[i+1])
                break
            elif args[i] == "blockConnectionsFromIP" or args[i] == "unblockConnectionsFromIP":
                self.IPRule(args[i], args[i+1])
                break
            elif args[i] == "blockUDP" or args[i] == "unblockUDP":
                self.UDPRule(args[i])
                break
            elif args[i] == "limitConnections":
                self.limitConnections(args[i], args[i+1], args[i+2])
                break
            elif args[i] == "limitOpConnections":
                self.limitOpConnections(args[i], args[i+1], args[i+2])
            else:
                print "incorrect command"

    def stop(self):
        """Stop the firewall."""
        os.system('sudo iptables -F')

    def usage(self, prog):
        sys.stderr.write("Usage: %s start|stop\n" % prog)

    def ICMPRule(self,command):
        if command == "inputDrop":
            print "inputDrop"
            rule = iptc.Rule()
            rule.protocol = "icmp"
            match = iptc.Match(rule, "icmp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
        elif command == "inputAccept":
            print "inputAccept"
            rule = iptc.Rule()
            rule.protocol = "icmp"
            match = iptc.Match(rule, "icmp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
        elif command == "outputDrop":
            print "outputDrop"
            rule = iptc.Rule()
            rule.protocol = "icmp"
            match = iptc.Match(rule, "icmp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
        elif command == "outputAccept":
            print "outputAccept"
            rule = iptc.Rule()
            rule.protocol = "icmp"
            match = iptc.Match(rule, "icmp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
        else:
            self.stop()

    def facebookRule(self, command):
        #get IP address of facebook
        hostQuery = ["host -t a " + "www.facebook.com"]
        host = subprocess.Popen(hostQuery,stdout=subprocess.PIPE, shell=True)
        (out,err) = host.communicate()

        #get the ip address using regex
        ipHost = re.findall('[0-9]+(?:\.[0-9]+){3}',out)

        #find the inet address range of the ip address found above
        query = ["whois " + ipHost[0] + " | grep inetnum"]
        whois = subprocess.Popen(query, stdout=subprocess.PIPE, shell=True)
        (out,err) = whois.communicate()

        #find the IP range of inet address
        ipRange = re.findall('[0-9]+(?:\.[0-9]+){3}', out)

        #convert IP range to cidr notation
        cidrs = netaddr.iprange_to_cidrs(ipRange[0], ipRange[1])

        #create rule based on command
        if command == "blockFacebook":
            #create rule to block facebook
            rule = iptc.Rule()
            rule.protocol = "tcp"
            rule.dst = str(cidrs[0])
            match = iptc.Match(rule, "tcp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Facebook Blocked"

        elif command == "unblockFacebook":
            # create rule to block facebook
            rule = iptc.Rule()
            rule.protocol = "tcp"
            rule.dst = str(cidrs[0])
            match = iptc.Match(rule, "tcp")
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Facebook Unblocked"
        else:
            self.stop()

    #To be modified yet
    def avoidDOSAttack(self):
        rule = iptc.Rule()
        rule.matches = "multiport"

    def macRule(self, command, macAddr):
        if command == "blockConnFromMAC":
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = str(macAddr)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Blocked connection from " + str(macAddr)
        elif command == "unBlockConnFromMAC":
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = str(macAddr)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Unblocked connection from " + str(macAddr)

        else:
            self.stop()

    def portRule(self, command, port):
        if command == "blockOutputPort":
            rule = iptc.Rule()
            rule.protocol = "tcp"
            match = iptc.Match(rule, "tcp")
            match.dport = str(port)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Blocked Output port: " + str(port)
        if command == "unblockOutputPort":
            rule = iptc.Rule()
            rule.protocol = "tcp"
            match = iptc.Match(rule, "tcp")
            match.dport = str(port)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Unblocked Output port: " + str(port)

    def limitConnections(self, command, port, number):
        if command == "limitConnections":
           os.system('iptables -A INPUT -p tcp --syn --dport ' +port+ ' -m connlimit '
                                                    '--connlimit-above '+ number+' -j REJECT')

    def limitOpConnections(self, command, port, number):
        if command == "limitOpConnections":
           os.system('iptables -A OUTPUT -p tcp --syn --dport ' +port+ ' -m connlimit '
                                                    '--connlimit-above '+ number+' -j REJECT')

    def IPRule(self,command, ip):
        if command == "blockConnectionsFromIP":
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            rule = iptc.Rule()
            rule.src = str(ip)
            target = iptc.Target(rule, "DROP")
            rule.target = target
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Blocked Connections from IP"
        elif command == "unblockConnectionsFromIP":
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            rule = iptc.Rule()
            rule.src = str(ip)
            target = iptc.Target(rule, "ACCEPT")
            rule.target = target
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "Unblocked Connections from IP"
        else:
            self.stop()

    def UDPRule(self,command):
        if command == "blockUDP":
            rule = iptc.Rule()
            rule.protocol = "udp"
            match = iptc.Match(rule, "udp")
            match.dport = "53"
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "UDP blocked"
        elif command == "unblockUDP":
            rule = iptc.Rule()
            rule.protocol = "udp"
            match = iptc.Match(rule, "udp")
            match.dport = "53"
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            self.logIntoFile(command)
            print "UDP blocked"
        else:
            self.stop()


    def logIntoFile(self,command):
        logFile = open('LogFile.txt','a')
        timeNow = time.asctime(time.localtime(time.time()))
        data = str(command) + ":" + str(timeNow)
        logFile.write(data + "\n")
        logFile.close()






obj = TwoWayStatelessFirewall().run(sys.argv)
