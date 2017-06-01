#!/usr/bin/python
# -*- coding: utf-8 -*-
from gi.repository import Gtk
import os
import subprocess
class Handler:
     def facebook_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start blockFacebook')
         print('Facebook Blocked.')
     def facebook_unblock(self, button):
         os.system('python TwoWayStatelessFirewall.py start unblockFacebook')
         print('Facebook Blocked.')
     def macbip_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start blockConnFromMAC '+mact1.get_text())
         print('Twitter Blocked.')
     def macbop_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start blockConnToMAC '+mact2.get_text())
         print('Twitter Blocked.')
     def macaip_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start unBlockConnFromMAC '+mact3.get_text())
         print('Twitter Blocked.')
     def macaop_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start unBlockConnToMAC '+mact4.get_text())
         print('Twitter Blocked.')
     def drop_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start inputDrop')
     def deleterules_clicked(self, button):
         os.system('sudo iptables -F')
     def udp1_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start blockUDP')
     def udp2_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start unblockUDP')
     def saverules_clicked(self, button):
         os.system('iptables-save > ~/iptables.rules')
     def limitip_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start limitConnections '+port.get_text()+' '+connections.get_text())
     def limitop_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start limitOpConnections '+portop.get_text()+' '+connectionsop.get_text())
     def add_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start inputAccept')
     def icmp3_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start outputAccept')
     def icmp4_clicked(self, button):
         os.system('python TwoWayStatelessFirewall.py start outputDrop')
     def tcp_output_block(self, button):
         os.system('python TwoWayStatelessFirewall.py start blockOutputPort '+blockport.get_text())
     def tcp_output_unblock(self, button):
         os.system('python TwoWayStatelessFirewall.py start unblockOutputPort '+unblockport.get_text())
     def view_clicked(self, button):
         text.set_buffer(buffer=None)
         proc = subprocess.Popen('sudo iptables -L'.split(), stdout=subprocess.PIPE, stderr =      subprocess.STDOUT)
         while True:
               line = proc.stdout.readline()
               text.get_buffer().insert_at_cursor(line)
               if not line:
	          break
           
     
    
   

builder = Gtk.Builder()
builder.add_from_file("newlayout.glade")
builder.connect_signals(Handler())
lock1 = builder.get_object("lock1")
lock2 = builder.get_object("lock2")
lock3 = builder.get_object("lock3")
lock4 = builder.get_object("lock4")
icmp1 = builder.get_object("icmp1")
icmp2 = builder.get_object("icmp2")
icmp3 = builder.get_object("icmp3")
icmp4 = builder.get_object("icmp4")
tcp1 = builder.get_object("tcp1")
tcp2 = builder.get_object("tcp2")
tcp3 = builder.get_object("tcp3")
view = builder.get_object("view")
delete = builder.get_object("delete")
save = builder.get_object("save")
text = builder.get_object("text")
port = builder.get_object("port")
connections = builder.get_object("connections")
port = builder.get_object("port")
connectionsop = builder.get_object("connectionsop")
portop = builder.get_object("portop")
blockport = builder.get_object("blockport")
unblockport = builder.get_object("unblockport")
mact1 = builder.get_object("mact1")
mact2 = builder.get_object("mact2")
mact3 = builder.get_object("mact3")
mact4 = builder.get_object("mact4")
mac1 = builder.get_object("mac1")
mac2 = builder.get_object("mac2")
mac3 = builder.get_object("mac3")
mac4 = builder.get_object("mac4")
udp1 = builder.get_object("udp1")
udp2 = builder.get_object("udp2")

	 
window = builder.get_object("window1")
window.connect("delete-event", Gtk.main_quit)
window.show_all()
	 
Gtk.main()
