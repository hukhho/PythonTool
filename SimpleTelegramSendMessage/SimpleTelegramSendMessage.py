
import urllib
import html2text
from BeautifulSoup import BeautifulSoup

soup = BeautifulSoup(urllib2.urlopen('http://example.com/page.html').read())

txt = soup.find('div', {'class' : 'body'})

print(html2text.html2text(txt))
