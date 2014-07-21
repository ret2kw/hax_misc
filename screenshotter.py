import sys
import selenium
from selenium import webdriver




def screenshot(url, savefile):


    phantomjs = '/root/Downloads/phantomjs-1.9.7-linux-i686/bin/phantomjs'
    serv_arg = ['--ignore-ssl-errors=true']

    driver = webdriver.PhantomJS(phantomjs, 
        service_args=serv_arg, 
        desired_capabilities={
        'phantomjs.page.settings.resourceTimeout' : '10000'})

    driver.set_page_load_timeout(10)

    try:
        driver.get(url)
    except selenium.common.exceptions.TimeoutException:
        print('[*] We got a timeout for %s' % url)
        return False

    print('[*] Screenshotting %s' % url)
    if driver.save_screenshot(savefile):
        return True

    else:
        print('[*] Failed to take a screenshot - Probably NTLM Auth')
        return False


ips = open(sys.argv[1], 'r').readlines()
port = sys.argv[2]


for ip in ips:
    #print('http://%s:%s/' % (ip.strip(), sys.argv[2]))
    #print('https://%s:%s/' % (ip.strip(), sys.argv[2]))
    
    url = 'http://%s:%s' % (ip.strip(), port)
    savefile = ip.strip() + '.png'
    screenshot(url, savefile)

    if sys.argv[3] == 'yes':
        url = 'https://%s:%s' % (ip.strip(), port)
        screenshot(url, 'https_' + savefile)











