import msfrpc
import time
import sys


client = msfrpc.Msfrpc({})
client.login('msf', '<insert_pass>')
res = client.call('console.create')
cid = res['id']


rhosts = [line.rstrip() for line in open(sys.argv[1], 'r')]
rhosts = ' ,'.join(rhosts)

match = unicode(sys.argv[2])

cmd = """use auxiliary/scanner/smb/smb_enumusers_domain
set RHOSTS %s
set SMBDomain <insert_domain>
set SMBPass <insert_pass>
set SMBUser <insert_user>
set THREADS 10
show options
exploit
exploit"""  % rhosts


client.call('console.write',[cid,cmd])
time.sleep(1)


foo = ''
while True:
    res = client.call('console.read',[cid])
    if '[*]' in res['data']:
        foo += res['data']   

    if res['busy'] == True:
        print('busy')
        time.sleep(1)
        continue

    break


for line in foo.split('\n'):
    if '[*]' in line:
        try:
            line.split(':')[1]
            print line.split(':')[0]

            for du in line.split(':')[1].split(' '):
                du = du.replace('\x00', '')
                if match in du:
                    print 'matched!! %s' % du

        except IndexError:
            pass


client.call('console.destroy',[cid])
