import ac
import traceback
import os
import webbrowser
from base64 import b64decode
import sys
import time
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../tsm_libraries"))

try:
    import ctypes.wintypes
except:
    ac.log('TheSetupMarket logs | error loading ctypes.wintypes: ' + traceback.format_exc())
    raise

from ctypes.wintypes import MAX_PATH

# TODO: read from config file for filters | IMPORTS
from os.path import dirname, realpath
#import configparser

import functools
import threading

try:
    from tsm.steam_utils.steam_info import get_steam_username, get_steam_id
except:
    ac.log('TheSetupMarket logs | error loading get_steam_username, get_steam_id: ' + traceback.format_exc())
    raise

def async(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()
        return t
    return wrapper


try:
    from tsm_libraries import requests
except Exception as e:
    ac.log('TheSetupMarket logs | Error: Could not import requests ' + traceback.format_exc())
    raise

try:
    import Crypto
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
except Exception as e:
    ac.log('TheSetupMarket logs | Error: Could not import Crypto ' + traceback.format_exc())
    raise

server_url = "http://unofficialsetupmarket.herokuapp.com"
sim_id = "null"
user_steamid = ""
session = requests.Session()

try:
    pKeyFile = open('./TSMPrivateKey.json')
    encryptionKeys = json.load(pKeyFile)
    pKeyFile.close()
except IOError:
    encryptionKeys = {}    

# read certificate file

# TODO: read from config file for filters
#config_path = dirname(realpath(__file__))

#config_ini_file = config_path + '/../config/config.ini'

#config = configparser.ConfigParser()
#config.read(config_ini_file, encoding='utf-8')
#config.sections()
#sim_versions = config['filters']['SimVersion']

#######################################
# Functions for setups download section
#######################################



def getSetups(car_code, currentTrackBaseName, currentTrackLayout):
    try:
        resp = session.get(server_url + '/api/get-setups-for-app/?car=' + car_code)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | error requesting setups from tsm api: ' + str(e))

    try:
        setups = resp.json()
    except Exception as e:
        ac.log('TheSetupMarket logs | error getSetups resp.json(): ' + str(e))
        setups = []


    trackSpecificSetups = []
    anyTracksSetups = []
    otherTrackSetups = []

    # TODO: sort and filter setups with config file
    #ac.log(str(setups.sort(key=extract_sim_version)))

    for setup in setups:
        if setup['car']['ac_code'] == car_code:
            if currentTrackBaseName in setup['track']['ac_code']:
                trackSpecificSetups.append(setup)
            elif setup['track']['ac_code'] == 'baseline':
                anyTracksSetups.append(setup)
            elif not currentTrackBaseName in setup['track']['ac_code'] and setup['track']['ac_code'] != 'baseline':
                otherTrackSetups.append(setup)

    categorizedSetupsObj = {}
    categorizedSetupsObj['trackSpecific'] = list(reversed(trackSpecificSetups))
    categorizedSetupsObj['anyTracks'] = list(reversed(anyTracksSetups))
    categorizedSetupsObj['otherTracks'] = list(reversed(otherTrackSetups))

    return categorizedSetupsObj


#######################################################
# /setup_files/[SIM ID]/[SETUP ID]
# Downloads a setup
# Server returns the setup file, under r.iter_content
#######################################################
@async
def downloadSetup(setup_id, setup_file_name, car_ac_code, track_baseName, track_layout, refreshSetupsListingTable):
    url = server_url + '/setup_files/' + sim_id + '/' + setup_id + '/'

    path_to_save = get_personal_folder() + r'\Assetto Corsa\setups' + '\\' + car_ac_code + '\\' + track_baseName + '\\' + setup_file_name

    try:
        r = session.get(url)
    except:
        ac.log('TheSetupMarket logs | downloadSetup failed at r = session.get(url)')
        r = {}
        r['status_code'] = ''

    if r.status_code == 200:
        try:
            with open(path_to_save, 'wb') as fd:
                for chunk in r.iter_content(chunk_size=1):
                    fd.write(chunk)
        except:
            ac.log('TheSetupMarket logs | could not find folder to save')

    else:
        ac.log('TheSetupMarket logs | setupid: ' + setup_id + 'error while downloading')

    refreshSetupsListingTable()


#######################################
# Functions for setups upload section
#######################################

# Gets setups from the local storage, server not involved
def getAllSetupsFromFolder(car_ac_code, track_baseName):
    # List setup files in current track folder
    try:
        allSetupFiles = os.listdir(get_personal_folder() + r'\Assetto Corsa\setups' + '\\' + car_ac_code + '\\' + track_baseName)
        ac.log('TheSetupMarket logs | getAllSetupsFromFolder: all setups in folder = ' + str(allSetupFiles))
    except:
        ac.log('TheSetupMarket logs | getAllSetupsFromFolder failed at allSetupFiles = os.listdir')
        return []

    # Build a new list without all files downloaded by the app (files starting with TSM)
    allSetupFilesNotTSM = []

    for setupFile in allSetupFiles:
        if '.sp' not in setupFile:
            allSetupFilesNotTSM.append(setupFile)

    ac.log('TheSetupMarket logs | all setups in folder not TSM: ' + str(allSetupFilesNotTSM))

    return allSetupFilesNotTSM


# def filterSetups(setupList, predicateName, predicateValue):
#     filteredSetupList = []
#
#     for setup in setupList:
#         if setup[predicateName] == predicateValue:
#             filteredSetupList.append(setup)
#
#     return filteredSetupList



#######################################################
# /api/create-setup/
# Uploads a setup
# User sends file, {'file_name': filename, 'sim_id': sim_id, 'sim_version': ac_version, 'user_id': userTSMId, 'car_id': car_id, 'track_id': track_id, 'trim': trim, 'best_laptime': '', 'comments': ''}
# Server returns status code - 200 for success
#######################################################
def uploadSetup(userTSMId, ac_version, user_steamId, filename, trim, baseline, car_id, track_id, car_ac_code, track_baseName, track_layout):

    if track_layout != '':
        track_ac_code = track_baseName + '-' + track_layout
    else:
        track_ac_code = track_baseName

    ac.log('TheSetupMarket logs | uploadSetup params: ' + str(filename) + ', ' + str(trim) + ', ' +  str(baseline) + ', ' + str(car_id) + ', ' + str(track_id))

    filepath = get_personal_folder() + r'\Assetto Corsa\setups' + '\\' + car_ac_code + '\\' + track_baseName + '\\' + filename
    ac.log('TheSetupMarket logs | uploadSetup filepath: ' + str(filepath))

    # params for API call
    url = server_url + '/api/create-setup/'
    file = {'file': open(filepath, 'rb')}

    if baseline:
        track_id = get_trackid_from_api('baseline')
    else:
        track_id = track_id

    trim = trim.lower()

    try:
        r = session.post(url, files=file, data={'file_name': filename, 'sim_id': sim_id, 'sim_version': ac_version,
        'user_id': userTSMId, 'car_id': car_id, 'track_id': track_id, 'trim': trim, 'best_laptime': '', 'comments': ''})
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | uploadSetup request failed! Status code: ' + str(e))


    if r.status_code == 200:
        ac.log('TheSetupMarket logs | upload request success! Status code: ' + str(r.status_code))
        return True
    else:
        ac.log('TheSetupMarket logs | upload request failed! Status code: ' + str(r.status_code))
        ac.log('TheSetupMarket logs | upload request failed! text: ' + str(r.text))
        ac.log('TheSetupMarket logs | upload request failed! content: ' + str(r.content))
        return False

#######################################################
# /api/get-setups-by-user/[USER ID]
# Gets all setups from a user
# Server returns JSON array of setups (see format below)
#######################################################
def getUserSetups(userTSMId, car_id, track_id):
    try:
        resp = session.get(server_url + '/api/get-setups-by-user/' + userTSMId + '/' + car_id)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | getUserSetups error request!: ' + str(e))

    try:
        setups = resp.json()
    except Exception as e:
        ac.log('TheSetupMarket logs | getUserSetups error resp.json(): ' + str(e))
        setups = []

    trackSpecificSetups = []
    otherTrackSetups = []

    for setup in setups:
        if setup['car']['_id'] == car_id:
            if setup['track']['_id'] == track_id or setup['track']['ac_code'] == 'baseline':
                trackSpecificSetups.append(setup)
            else:
                otherTrackSetups.append(setup)

    categorizedSetupsObj = {}
    categorizedSetupsObj['trackSpecific'] = list(reversed(trackSpecificSetups))
    categorizedSetupsObj['otherTracks'] = list(reversed(otherTrackSetups))

    return categorizedSetupsObj

#######################################################
# /api/get-setup/[SETUP ID]
# Gets setup from setup id
# Server returns setup as JSON {file_name: "string.ini", type: "qualy" | "race", best_time: int/ double?, comments: array?, track: {_id: "track_id"}}
# Could be more info but i cant see it right now
#######################################################
@async
def getSetupDetails(setupId, callback):
    try:
        resp = session.get(server_url + '/api/get-setup/' + setupId)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | error requesting user setup details from tsm api: ' + str(e))

    try:
        setupDetail = resp.json()
    except Exception as e:
        ac.log('TheSetupMarket logs | error requesting user setups from tsm api: ' + str(e))

    callback(setupDetail)

    return setupDetail

# Setup.update({_id: request.body.setup_id}, {sim_version: request.body.sim_version, type: request.body.trim, best_time: request.body.best_laptime, comments: request.body.comments}, function(err, numAffected) {

#######################################################
# /api/update-setup-with-file/
# Updates a setup on the server
# Should probably make sim_id a global var so that it can be used in other functions, easier to update if it changes on the backend
# Will need to see how it sends the file data
# Will need to do some server side verification of the file to make sure its nothing malicious
#######################################################
@async
def updateSetup(car_ac_code, track_baseName, file_name, setup_id, car_id, track_id, sim_version, trim, baseline, best_time, comments, callback):
    filepath = get_personal_folder() + r'\Assetto Corsa\setups' + '\\' + car_ac_code + '\\' + track_baseName + '\\' + file_name
    ac.log('TheSetupMarket logs | updateSetup filepath: ' + str(filepath))

    # params for API call
    url = server_url + '/api/update-setup-with-file/'
    file = {'file': open(filepath, 'rb')}

    if baseline:
        track_id = get_trackid_from_api('baseline')

    trim = trim.lower()

    try:
        r = session.post(url, files=file,
                          data={'sim_id': sim_id, 'setup_id': setup_id, 'file_name': file_name, 'sim_version': sim_version,
                                'car_id': car_id, 'track_id': track_id, 'trim': trim, 'best_laptime': best_time, 'comments': comments})
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | updateSetup error request!: ' + str(e))


    if r.status_code == 200:
        ac.log('TheSetupMarket logs | update request success! Status code: ' + str(r.status_code))
        returnMessage = 'Setup successfully updated'
    else:
        ac.log('TheSetupMarket logs | update request failed! Status code: ' + str(r.status_code))
        ac.log('TheSetupMarket logs | update request failed! text: ' + str(r.text))
        ac.log('TheSetupMarket logs | update request failed! content: ' + str(r.content))
        returnMessage = 'Error updating setup'

    callback(returnMessage)


@async
def sendSetupRating(userSteamId, setupId, userRating):
    url = server_url + '/api/update-setup-rating-from-app/'

    try:
        r = session.post(url, data={'userSteamId': userSteamId, 'userRating': userRating, 'setupId': setupId})
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | sendSetupRating error request!: ' + str(e))

    if r.status_code == 200:
        ac.log('TheSetupMarket logs | sendSetupRating request success! Status code: ' + str(r.status_code))
    else:
        ac.log('TheSetupMarket logs | sendSetupRating request failed! Status code: ' + str(r.status_code))
        ac.log('TheSetupMarket logs | sendSetupRating request failed! text: ' + str(r.text))
        ac.log('TheSetupMarket logs | sendSetupRating request failed! content: ' + str(r.content))


#######################################
# Utilitary functions
#######################################
def get_personal_folder():
    dll = ctypes.windll.shell32
    buf = ctypes.create_unicode_buffer(MAX_PATH + 1)
    if dll.SHGetSpecialFolderPathW(None, buf, 0x0005, False):
        return buf.value
    else:
        raise Exception('TheSetupMarket logs | Could not find "Documents" folder')


# def extract_sim_version(setup):
#     try:
#         return setup['sim_version']
#     except KeyError:
#         return 0

#######################################################
# /api/get-sim-infos/[SIM NAME]
# Gets information about the sim
# Server returns JSON containing {versions: ["version", "version"...]}
# Could be more data but that is unknown/ not necessary
#######################################################
def get_ac_version_from_api():
    url = server_url + '/api/get-sim-infos/Assetto%20Corsa'

    try:
        r = session.get(url)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | get_ac_version_from_api error request!: ' + str(e))


    if r.status_code == 200:
        try:
            request_json = r.json()
            global sim_id
            sim_id = request_json['_id']
            ac_versions = request_json['versions']
            ac_current_version = ac_versions[-1]
        except:
            ac.log('TheSetupMarket logs | get_ac_version_from_api failed at request_json = r.json()')
            ac_current_version = False
    else:
        ac.log('TheSetupMarket logs | get_ac_version_from_api failed. status_code = ' + str(r.status_code))
        ac_current_version = False

    return ac_current_version

#######################################################
# /api/get-car-by-accode/[CAR CODE]
# Gets ID for car from server using internal game code
# Server returns JSON containing {_id: "string"}
#######################################################

def get_carid_from_api(ac_code):
    url = server_url + '/api/get-car-by-accode/' + ac_code

    try:
        r = session.get(url)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | get_carid_from_api error request!: ' + str(e))

    if r.status_code == 200:
        try:
            request_json = r.json()
            carId = request_json['_id']
        except:
            carId = False

    else:
        ac.log('TheSetupMarket logs | get_carid_from_api failed. status_code = ' + str(r.status_code))
        carId = False

    return carId

#######################################################
# /api/get-track-accode/[TRACK CODE]
# Gets ID for track from server using internal game code
# Server returns JSON containing {_id: "string"}
#######################################################

def get_trackid_from_api(ac_code):
    url = server_url + '/api/get-track-by-accode/' + ac_code

    try:
        r = session.get(url)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | get_trackid_from_api error request!: ' + str(e))

    if r.status_code == 200:
        try:
            request_json = r.json()
            trackId = request_json['_id']
        except:
            trackId = False
    else:
        ac.log('TheSetupMarket logs | get_trackid_from_api failed. status_code = ' + str(r.status_code))
        trackId = False

    return trackId

#######################################################
# /api/get-user-by-steamId/[USER STEAM ID]
# Gets the user id using their steam id
# Server returns JSON containing {_id: "string"}
# This is probably where some kind of authentication is required to prevent the databases being wiped
# One technique would be for the user to login from browser to add a key/ IP which would have to be matched to make any changes
# Or user logs in with browser to verify steam id, they then get a private key which can be entered into tsm to authenticate through a keypair encrypt/ decrypt
# We'll then need a way to store some kind of session key which can be given with requests, or maybe just authenticate the IP for 24 hours
#######################################################

def getUserTSMIdWithSteamID(steamID):
    url = server_url + '/api/get-user-by-steamId/' + str(steamID)
    global user_steamid
    user_steamid = str(steamID)
    userTSMId = False

    try:
        r = session.get(url)
    except requests.exceptions.RequestException as e:
        ac.log('TheSetupMarket logs | getUserTSMIdWithSteamID error request!: ' + str(e))

    if r.status_code == 200:
        try:
            request_json = r.json()
            if "error" in request_json:
                # user does not exist
                userTSMId = getNewPrivkey(steamID)
                authenticate(userTSMId)
            elif '_id' in request_json:
                userTSMId = request_json['_id']
                if not (userTSMId in encryptionKeys):
                    userTSMId = getNewPrivkey(steamID)
                authenticate(userTSMId)

        except:
            ac.log('TheSetupMarket logs | getUserTSMIdWithSteamID failed at request_json = r.json() = ')
    else:
        ac.log('TheSetupMarket logs | getUserTSMIdWithSteamID failed. status_code = ' + str(r.status_code))
        return '502'

    return userTSMId

def getNewPrivkey(steamID):
    webbrowser.open_new(server_url + '/auth/steam')
    hasKey = False
    temp_userid = ""
    while not hasKey:
        newPrivateKey = session.get(server_url + '/auth/get-new-privkey/' + str(steamID))
        newPrivateKey_json = newPrivateKey.json()
        if 'privateKey' in newPrivateKey_json:
            temp_userid = newPrivateKey_json['user_id']
            encryptionKeys[temp_userid] = newPrivateKey_json['privateKey']
            keyFile = open('./TSMPrivateKey.json', "w")
            json.dump(encryptionKeys, keyFile)
            hasKey = True
        else:
            ac.log("TSM Auth | Error: private key not in response")
        time.sleep(2)
    return temp_userid

def authenticate(userTSMId):
    auth_data_request = session.get(server_url + "/auth/get-encrypted-data/" + userTSMId)
    auth_data_json = auth_data_request.json()
    encrypted_data = auth_data_json['data']
    # private_key = serialization.load_pem_private_key(
    #     encryptionKeys[userTSMId],
    #     password=None,
    #     backend=default_backend()
    # )
    # decrypted_data = private_key.decrypt(encrypted_data)

    rsa_key = RSA.importKey(encryptionKeys[userTSMId])
    cipher = PKCS1_OAEP.new(rsa_key)
    raw_cipher_data = b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(raw_cipher_data).decode('utf-8')

    login_request = session.post(server_url + "/auth/app-login/", data={'username': userTSMId, 'password': decrypted_data})
    if login_request.status_code == 200:
        ac.log("TSM | success, logged in")
    else:
        ac.log("TSM Auth | Error: decrypted data does not match server")
        time.sleep(2)
        ac.log("TSM Auth | Retrying authentication")
        authenticate(getNewPrivkey(user_steamid))


def getUserSteamId():
    return get_steam_id()


def getUserSteamUsername():
    return get_steam_username()
