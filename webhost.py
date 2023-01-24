#Imports

from flask import Flask, request, session, redirect, send_file, render_template, abort
from json import loads, dumps
from datetime import datetime
from time import time
from requests import post, get
from uuid import uuid4
from gc import collect
import urllib.parse

#Loading databases (files not public)

databasePath='/var/www/html/peoplelist.json'
sessionsPath='/var/www/html/sessions.json'
usersPath='/var/www/html/users.json'
adminsPath='/var/www/html/admins.json'
templatePath='/var/www/html/templates'

database=loads(open(databasePath,'r').read())
sessions=loads(open(sessionsPath,'r').read())
admins=loads(open(adminsPath,'r').read())

#Define main flask app

app = Flask(__name__, template_folder=templatePath)

#Define helper functions

def reloadSessionDatabase():
    global sessions
    sessions=loads(open(sessionsPath, 'r').read())

def invalidateExpiredSessions():
    reloadSessionDatabase()
    global sessions
    for session in sessions['sessions']:
        if(int(session['expiry']) <= int(time())):
            sessions['sessions'].remove(session)
    open(sessionsPath, 'w').write(dumps(sessions))
    collect()

def validateSession(userSession):
    if('session-id' in userSession):
        if(loads(userSession['session-id']) in sessions['sessions']):
            return True
    return False  

def extendSession(userSession):
    global sessions
    if('session-id' in userSession):
        userData=loads(userSession['session-id'])
        for i in range(len(sessions['sessions'])):
            if(userData == sessions['sessions'][i]):
                expiryTime = str(int(time()+1800))
                sessions['sessions'][i]['expiry'] = expiryTime
                session['session-id']=dumps(sessions['sessions'][i])
        open(sessionsPath, 'w').write(dumps(sessions))

#/

@app.route('/')
def home():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login',code='302')
    extendSession(session)
    person=loads(session['session-id'])['uid']
    homeData=''
    if(person in database):
        homeData=render_template('image.html',ID=database[person]['id'],name=database[person]['name'],grade=database[person]['grade'],email=database[person]['email'],image=database[person]['photo'])
    if(person in admins):
        homeData+="<p style='color: blue;'>Congrats, you are an admin.</p>"
        if("viewUsers" in admins[person]['permissions']):
            homeData+='<p>Users:</p>'
            users=loads(open(usersPath,'r').read())
            for user in users:
                if(user in database):
                    admin='REDACTED'
                    if('viewAdminStatus' in admins[person]['permissions']):
                        admin='No'
                        if(user in admins):
                            admin='Yes'
                    ipAddresses='REDACTED'
                    if('viewIPs' in admins[person]['permissions']):
                        ipAddresses=''
                        for address in users[user]['knownIPs']:
                            ipAddresses+=address+', '
                    lastTime='REDACTED'
                    if('viewLoginDate' in admins[person]['permissions']):
                        lastTime=datetime.fromtimestamp(int(users[user]['lastLoginTime']))
                    homeData+=render_template('imageAdmin.html',ID=database[user]['id'],name=database[user]['name'],grade=database[user]['grade'],email=database[user]['email'],lastLoginTime=lastTime,ipAddresses=ipAddresses,image=database[user]['photo'],admin=admin)
                else:
                    ipAddresses='REDACTED'
                    if('viewIPs' in admins[person]['permissions']):
                        ipAddresses=''
                        for address in users[user]['knownIPs']:
                            ipAddresses+=address+', '
                    homeData+=render_template('imageAdmin.html',ID=user,name='Unknown',grade='Unknown',email='Unknown',lastLoginTime=datetime.fromtimestamp(int(users[user]['lastLoginTime'])),ipAddresses=ipAddresses,image='about:blank',admin='Unknown')
    return render_template('search.html',text='',action='/') + homeData + render_template('changelog.html')

@app.route('/', methods=['POST'])
def rootToSearch():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    return redirect("/search?query="+urllib.parse.quote(request.form['text_string'])+'&page=0'+'&method='+request.form['method'], code=302)

#/search

@app.route('/search')
def search():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    users=loads(open(usersPath,'r').read())
    person = request.args.get('query')
    users[loads(session['session-id'])['uid']]['searchHistory'].append({'time':str(int(time())),'query':person})
    open(usersPath,'w').write(dumps(users))
    page = int(request.args.get('page'))
    method = request.args.get('method')
    if(method == 'id'):
        if(person in database):
            return render_template('search.html', text=person,action='/') + render_template('image.html',ID=database[person]['id'],name=database[person]['name'],grade=database[person]['grade'],email=database[person]['email'],image=database[person]['photo'])
        else:
            return render_template('search.html',text=person,action='/')+'''
                <p>No Results</p>
                <p> </p>
                <p>Since we couldn't find who you were looking for, here is a list of all of your friends</p>
                <p></p>
                <p style="color: white;">Get it, there's nothing here.</p>
            '''
    elif(method in ['name','grade','email']):
        results = []
        for persons in database:
            persons = database[persons]
            if(person.lower() in persons[method].lower()):
                results.append(persons)
        if(len(results) > 0):
            searchData=render_template('search.html',text=person,action='/')
            if(page>0):
                searchData+='<a href="/search?query='+person+'&page='+str(page-1)+'&method='+method+'"><button><p>Prev. Page</p></button></a>'
            if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                searchData+='<a href="/search?query='+person+'&page='+str(page+1)+'&method='+method+'"><button><p>Next Page</p></button></a>'
            for result in results[page*10:page*10+10]:
                searchData+=render_template('image.html',ID=result['id'],name=result['name'],grade=result['grade'],email=result['email'],image=result['photo'])
            if(page>0):
                searchData+='<a href="/search?query='+person+'&page='+str(page-1)+'&method='+method+'"><button><p>Prev. Page</p></button></a>'
            if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                searchData+='<a href="/search?query='+person+'&page='+str(page+1)+'&method='+method+'"><button><p>Next Page</p></button></a>'
            return searchData
        return render_template('search.html',text=person,action='/')+'''
            <p>No Results</p>
            <p> </p>
            <p>Since we couldn't find who you were looking for, here is a list of all of your friends</p>
            <p></p>
            <p style="color: white;">Get it, there's nothing here.</p>
        '''
    
#/image

@app.route('/image')
def image():
    try:
        name = request.args.get('name')
        with open('/tmp/'+name, 'wb') as file:
            resp = get('https://esdportal.graniteschools.org/image.ashx?name='+name, headers={'referer':'https://esdportal.graniteschools.org'})
            if(resp.status_code == 200):
                file.write(resp.content)
                return send_file('/tmp/'+name, mimetype='image/jpeg')
            else:
                return send_file('/var/www/html/notfound.jpg', mimetype='image/jpeg')
    except:
        return send_file('/var/www/html/notfound.jpg', mimetype='image/jpeg')

#/favoriteToggleHelper

@app.route('/favoriteToggleHelper')
def helpToggleFavorite():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    #if(request.headers.get("Referer")!='https://heresyourschoolphoto.win'):
    #    abort(403)
    users=loads(open(usersPath,'r').read())
    if(request.args.get('name') in users[loads(session['session-id'])['uid']]['favorites']):
        users[loads(session['session-id'])['uid']]['favorites'].remove(request.args.get('name'))
    else:
        users[loads(session['session-id'])['uid']]['favorites'].append(request.args.get('name'))
    open(usersPath,'w').write(dumps(users))
    return redirect('/favoriteToggle?name='+request.args.get('name'), code=302)

#/favoriteToggle

@app.route('/favoriteToggle')
def toggleFavorite():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    #if(request.headers.get("Referer")!='https://heresyourschoolphoto.win'):
    #    abort(403)
    users=loads(open(usersPath,'r').read())
    data=''
    if(request.args.get('name') in users[loads(session['session-id'])['uid']]['favorites']):
        data='Un'
    return '<a href="/favoriteToggleHelper?name='+request.args.get('name')+'"><p>'+data+'Favorite</p></a>'

#/favorites

@app.route('/favorites', methods=['POST'])
def favoritesToSelf():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    if(request.args.get('override') != None):
        return redirect("/favorites?query="+urllib.parse.quote(request.form['text_string'])+'&page=0'+'&method='+request.form['method']+'&override='+request.args.get('override'), code=302)
    return redirect("/favorites?query="+urllib.parse.quote(request.form['text_string'])+'&page=0'+'&method='+request.form['method'], code=302)

@app.route('/favorites')
def favorites():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login', code=302)
    uid=loads(session['session-id'])['uid']
    users=loads(open(usersPath,'r').read())
    if(request.args.get('override') != None):
        if(uid in admins):
            if('viewFavorites' in admins[uid]['permissions']):
                if(request.args.get('override') in users):
                    uid=request.args.get('override')
                else:
                    abort(404)
            else:
                return "<h1>REDACTED</h1>"
        else:
            abort(403)
    query = request.args.get('query')
    page=request.args.get('page')
    if(page==None):
        page=0
    else:
        page=int(page)
    method=request.args.get('method')
    if(query == None):
        query=''
        results = users[uid]["favorites"]
        if(len(results) > 0):
            searchData=render_template('search.html',text=query,action='/favorites')
            if(request.args.get('override') != None):
                searchData=render_template('search.html',text=query,action='/favorites?override='+uid)
                if(page>0):
                    searchData+='<a href="/favorites?page='+str(page-1)+'&override='+uid+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?page='+str(page+1)+'&override='+uid+'"><button><p>Next Page</p></button></a>'
            else:
                if(page>0):
                    searchData+='<a href="/favorites?page='+str(page-1)+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?page='+str(page+1)+'"><button><p>Next Page</p></button></a>'
            for result in results[page*10:page*10+10]:
                result = database[result]
                searchData+=render_template('image.html',ID=result['id'],name=result['name'],grade=result['grade'],email=result['email'],image=result['photo'])
            if(request.args.get('override') != None):
                if(page>0):
                    searchData+='<a href="/favorites?page='+str(page-1)+'&override='+uid+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?page='+str(page+1)+'&override='+uid+'"><button><p>Next Page</p></button></a>'
            else:
                if(page>0):
                    searchData+='<a href="/favorites?page='+str(page-1)+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?page='+str(page+1)+'"><button><p>Next Page</p></button></a>'
            return searchData
    results=[]
    for favorite in users[uid]["favorites"]:
        if(query.lower() in database[favorite][method].lower()):
            results.append(favorite)
    if(len(results) > 0):
            page=int(page)
            searchData=render_template('search.html',text=query,action='/favorites')
            if(request.args.get('override') != None):
                searchData=render_template('search.html',text=query,action='/favorites?override='+uid)
                if(page>0):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page-1)+'&method='+method+'&override='+uid+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page+1)+'&method='+method+'&override='+uid+'"><button><p>Next Page</p></button></a>'
            else:
                if(page>0):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page-1)+'&method='+method+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page+1)+'&method='+method+'"><button><p>Next Page</p></button></a>'
            for result in results[page*10:page*10+10]:
                result = database[result]
                searchData+=render_template('image.html',ID=result['id'],name=result['name'],grade=result['grade'],email=result['email'],image=result['photo'])
            if(request.args.get('override') != None):
                if(page>0):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page-1)+'&method='+method+'&override='+uid+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page+1)+'&method='+method+'&override='+uid+'"><button><p>Next Page</p></button></a>'
            else:
                if(page>0):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page-1)+'&method='+method+'"><button><p>Prev. Page</p></button></a>'
                if(len(results[(page+1)*10:(page+1)*10+10])>=1):
                    searchData+='<a href="/favorites?query='+query+'&page='+str(page+1)+'&method='+method+'"><button><p>Next Page</p></button></a>'
            return searchData
    return render_template('search.html',text=query,action='/favorites')+'''
        <p>No Results</p>
        <p></p>
        <p style="color: white;">I told you, you have no friends.</p>
    '''
                        

#/login

@app.route('/login')
def sendLogin():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)):
        extendSession(session)
        return redirect('/', code=302)
    return render_template('login.html', header='Login With Granite School District', switchTo='/login/gradebook.win', switchToText='Or Login With Gradebook.win', error='')

@app.route('/login', methods=['POST'])
def validateLogin():
    global sessions
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)):
        extendSession(session)
        return redirect('/', code=302)
    username=request.form['username']
    password=request.form['password']
    loginResults = post("https://portalapps.graniteschools.org/", params={"ReturnUrl": "%2FStudentFiles%2FViewer"}, data={"UserName": username, "Password": password}, headers={"dnt": "1"}, cookies={"_ga": "GA1.2.175394362.1671044106", "CStoneSessionID": str(uuid4()), "ASP.NET_SessionId": str(uuid4())})
    #if(username != '0000000'):
    if(loginResults.text.splitlines()[len(loginResults.text.splitlines())-1:][0].strip() == '</html>'):
        return render_template('login.html', header='Login With Granite School District', switchTo='/login/gradebook.win', switchToText='Or Login With Gradebook.win', error="<p style='color: red;'>Incorrect Username or Password</p>")
    sessionStorage={'id':str(uuid4()),'expiry':str(int(time())+1800),'uid':username}
    session['session-id']=dumps(sessionStorage)
    sessions['sessions'].append(sessionStorage)
    open(sessionsPath, 'w').write(dumps(sessions))
    users=loads(open(usersPath,'r').read())
    if(username in users):
        if(str(request.remote_addr) not in users[username]['knownIPs']):
            users[username]['knownIPs'].append(str(request.remote_addr))
        users[username]['lastLoginTime']=str(int(time()))
    else:
        users[username]={}
        users[username]['knownIPs']=[str(request.remote_addr)]
        users[username]['lastLoginTime']=str(int(time()))
        users[username]['favorites']=[]
        users[username]['searchHistory']=[]
    open(usersPath,'w').write(dumps(users))
    with open('/var/www/html/access.log', 'a') as log:
        log.write('User ' + username + ' logged in at ' + str(int(time())) + ' from ' + str(request.remote_addr) + '\n')
    return redirect("/", code=302)

#/login/gradebook.win

@app.route('/login/gradebook.win')
def loginGradebook():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)):
        extendSession(session)
        return redirect('/', code=302)
    return render_template('login.html', header='Login With Gradebook.win', switchTo='/login', switchToText='Or Login With Granite School District', error='')

@app.route('/login/gradebook.win', methods=['POST'])
def validateLoginGradebook():
    global sessions
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)):
        extendSession(session)
        return redirect('/', code=302)
    username=request.form['username']
    password=request.form['password']
    resp=post('https://gradebook.win/api/auth', data={'username':username,'password':password})
    if('access_token' not in loads(resp.text)):
        return render_template('login.html', header='Login With Gradebook.win', switchTo='/login', switchToText='Or Login With Granite School District', error='<p style="color: red;">'+loads(resp.text)['detail']+'</p>')
    username = loads(get("https://gradebook.win/api/profile", headers={"authorization": "Bearer "+loads(resp.text)['access_token'], "dnt": "1"}, cookies={"token": loads(resp.text)['access_token']}).text)['data']['student_id']
    sessionStorage={'id':str(uuid4()),'expiry':str(int(time())+1800),'uid':username}
    session['session-id']=dumps(sessionStorage)
    sessions['sessions'].append(sessionStorage)
    open(sessionsPath, 'w').write(dumps(sessions))
    users=loads(open(usersPath,'r').read())
    if(username in users):
        if(str(request.remote_addr) not in users[username]['knownIPs']):
            users[username]['knownIPs'].append(str(request.remote_addr))
        users[username]['lastLoginTime']=str(int(time()))
    else:
        users[username]['knownIPs']=[str(request.remote_addr)]
        users[username]['lastLoginTime']=str(int(time()))
        users[username]['favorites']=[]
        users[username]['searchHistory']=[]
    open(usersPath,'w').write(dumps(users))
    with open('/var/www/html/access.log', 'a') as log:
        log.write('User ' + username + ' logged in at ' + str(int(time())) + ' from ' + str(request.remote_addr) + '\n')
    return redirect("/", code=302)

#/searchHistory

@app.route('/searchHistory')
def searchHistory():
    invalidateExpiredSessions()
    reloadSessionDatabase()
    if(validateSession(session)==False):
        return redirect('/login',code='302')
    extendSession(session)
    person=loads(session['session-id'])['uid']
    if(person in admins):
        if('viewSearchHistory' in admins[person]['permissions']):
            name = request.args.get('name')
            users=loads(open(usersPath,'r').read())
            data=''
            for search in users[name]['searchHistory']:
                query=search['query']
                if(('<' in query) or ('>' in query)):
                    query=query.replace('<','').replace('>','')
                    data='<p>['+str(datetime.fromtimestamp(int(search['time'])))+'] "'+query+'" "<" and ">" removed to prevent XSS (Cross Site Scripting) injection.</p><p></p>'+data
                else:
                    data='<p>['+str(datetime.fromtimestamp(int(search['time'])))+'] "'+query+'"</p><p></p>'+data
            return data
        else:
            return '<h1>REDACTED</h1>'
    abort(403)

#/logout

@app.route('/logout')
def logout():
    global sessions
    reloadSessionDatabase()
    if('session-id' in session):
        if(loads(session['session-id']) in sessions['sessions']):
            for sessionss in sessions['sessions']:
                if(loads(session['session-id']) == sessionss):
                    sessions['sessions'].remove(sessionss)
    open(sessionsPath, 'w').write(dumps(sessions))
    return redirect("/login", code=302)

#For devel



if __name__ == '__main__':
    app.run()
