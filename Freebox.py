#!/usr/bin/python3
"""Ce programme a pour objectif de contrôler la Freebox via son API."""
import configparser
import json
import os
import argparse
import requests
from Crypto.Hash import SHA, HMAC
#from pprint import pprint

# Fichier de configuration par défaut
INIFILE = "fbx.ini"
# Root CA certificat de la freebox tel que défini dans la documentation de l'API Freebox
FREEBOX_ROOT_CA = """
-----BEGIN CERTIFICATE-----
MIIFmjCCA4KgAwIBAgIJAKLyz15lYOrYMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNV
BAYTAkZSMQ8wDQYDVQQIDAZGcmFuY2UxDjAMBgNVBAcMBVBhcmlzMRAwDgYDVQQK
DAdGcmVlYm94MRgwFgYDVQQDDA9GcmVlYm94IFJvb3QgQ0EwHhcNMTUwNzMwMTUw
OTIwWhcNMzUwNzI1MTUwOTIwWjBaMQswCQYDVQQGEwJGUjEPMA0GA1UECAwGRnJh
bmNlMQ4wDAYDVQQHDAVQYXJpczEQMA4GA1UECgwHRnJlZWJveDEYMBYGA1UEAwwP
RnJlZWJveCBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
xqYIvq8538SH6BJ99jDlOPoyDBrlwKEp879oYplicTC2/p0X66R/ft0en1uSQadC
sL/JTyfgyJAgI1Dq2Y5EYVT/7G6GBtVH6Bxa713mM+I/v0JlTGFalgMqamMuIRDQ
tdyvqEIs8DcfGB/1l2A8UhKOFbHQsMcigxOe9ZodMhtVNn0mUyG+9Zgu1e/YMhsS
iG4Kqap6TGtk80yruS1mMWVSgLOq9F5BGD4rlNlWLo0C3R10mFCpqvsFU+g4kYoA
dTxaIpi1pgng3CGLE0FXgwstJz8RBaZObYEslEYKDzmer5zrU1pVHiwkjsgwbnuy
WtM1Xry3Jxc7N/i1rxFmN/4l/Tcb1F7x4yVZmrzbQVptKSmyTEvPvpzqzdxVWuYi
qIFSe/njl8dX9v5hjbMo4CeLuXIRE4nSq2A7GBm4j9Zb6/l2WIBpnCKtwUVlroKw
NBgB6zHg5WI9nWGuy3ozpP4zyxqXhaTgrQcDDIG/SQS1GOXKGdkCcSa+VkJ0jTf5
od7PxBn9/TuN0yYdgQK3YDjD9F9+CLp8QZK1bnPdVGywPfL1iztngF9J6JohTyL/
VMvpWfS/X6R4Y3p8/eSio4BNuPvm9r0xp6IMpW92V8SYL0N6TQQxzZYgkLV7TbQI
Hw6v64yMbbF0YS9VjS0sFpZcFERVQiodRu7nYNC1jy8CAwEAAaNjMGEwHQYDVR0O
BBYEFD2erMkECujilR0BuER09FdsYIebMB8GA1UdIwQYMBaAFD2erMkECujilR0B
uER09FdsYIebMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqG
SIb3DQEBCwUAA4ICAQAZ2Nx8mWIWckNY8X2t/ymmCbcKxGw8Hn3BfTDcUWQ7GLRf
MGzTqxGSLBQ5tENaclbtTpNrqPv2k6LY0VjfrKoTSS8JfXkm6+FUtyXpsGK8MrLL
hZ/YdADTfbbWOjjD0VaPUoglvo2N4n7rOuRxVYIij11fL/wl3OUZ7GHLgL3qXSz0
+RGW+1oZo8HQ7pb6RwLfv42Gf+2gyNBckM7VVh9R19UkLCsHFqhFBbUmqwJgNA2/
3twgV6Y26qlyHXXODUfV3arLCwFoNB+IIrde1E/JoOry9oKvF8DZTo/Qm6o2KsdZ
dxs/YcIUsCvKX8WCKtH6la/kFCUcXIb8f1u+Y4pjj3PBmKI/1+Rs9GqB0kt1otyx
Q6bqxqBSgsrkuhCfRxwjbfBgmXjIZ/a4muY5uMI0gbl9zbMFEJHDojhH6TUB5qd0
JJlI61gldaT5Ci1aLbvVcJtdeGhElf7pOE9JrXINpP3NOJJaUSueAvxyj/WWoo0v
4KO7njox8F6jCHALNDLdTsX0FTGmUZ/s/QfJry3VNwyjCyWDy1ra4KWoqt6U7SzM
d5jENIZChM8TnDXJzqc+mu00cI3icn9bV9flYCXLTIsprB21wVSMh0XeBGylKxeB
S27oDfFq04XSox7JM9HdTt2hLK96x1T7FpFrBTnALzb7vHv9MhXqAT90fPR/8A==
-----END CERTIFICATE-----
"""
# Information d'authentification
AUTHINFO = {
    "login": "freebox",
    "passwd": ""
    }
# ID de l'application présenté à la freebox
APPID = "org.tuxfarm.pyfbx"
# Nom de l'applicatoin
APPNAME = "pyfbx"
# Version de l'application
APPVER = "0.0.1"
# Device => c'est un script
DEVICENAME = "script"

RQ_CONTENT = {
    "app_id": APPID,
    "app_name": APPNAME,
    "app_version": APPVER,
    "device_name": DEVICENAME
}


def make_digest(message, key):
    """
    Construit un hmac-sha1
    """
    key = key.encode('utf-8')
    message = message.encode('utf-8')
    digester = HMAC.new(key, message, SHA)
    return digester.hexdigest()


class Freebox:
    """ Classe permettant d'interagir avec une Freebox via son API"""
    # App token
    app_token = None
    # URL spécifique pour l'API
    createdurl = ""
    track_id = ""
    sessionData = None
    session_id = None
    challenge = None
    config = None
    query_verify = True

    def __init__(self):
        """Crée l'objet freebox"""
        self.config = configparser.ConfigParser()
        self.config.read(INIFILE)
        self.app_token = self.config.get('GENERAL', "app_token", fallback=False)

        # On définit la métohde de vérification de SSL avec le rootca de la FBX
        # voir la doc de l'api.
        s = requests.Session()
        s.verify = os.path.join(os.getcwd(), "eccrootca.crt")
        self.query_verify = s.verify

        content = requests.get("http://mafreebox.free.fr/api_version")
        if content.status_code != 200:
            raise Exception("Erreur de version d'API")

        urlcontent = content.json()
        api_major = urlcontent['api_version'].split('.')[0]
        url_placeholder = 'https://{api_domain}:{https_port}{api_base_url}'
        self.createdurl = url_placeholder.format(**urlcontent) + "v" + api_major + "/"
        print("Utilisation de {}".format(self.createdurl))

    def get_app_token(self):
        """Récupère l'APP token de la freebox, l'utilisateur doit accepter
        cet accès directement sur la freebox au moment de l'appel. Le token
        est ensuite placé dans le fichier ini."""
        if not self.app_token:
            try:
                authcont = self._query_freebox_json("post", "login/authorize/", RQ_CONTENT)
            except Exception as exc:
                raise Exception("Impossible d'initier l'autorisation : {}".format(exc))

            self.app_token = authcont['result']['app_token']
            self.track_id = authcont['result']['track_id']

            status_pending = True
            while status_pending:
                token_status = self._query_freebox_json("get", "login/authorize/{}".format(self.track_id))
                if token_status['result']['status'] in ['denied', 'timeout']:
                    raise Exception("Aucune autorisation freebox n'a été acceptée")
                status_pending = token_status['result']['status'] != "granted"
            # si on arrive là c'est que notre app token est ok

            with open(INIFILE, "w") as fp:
                self.config['GENERAL'] = {'app_token': self.app_token}
                self.config.write(fp)

    def login(self):
        """Effectue un login sur l'API Freebox et récupère une session"""
        # Challenging explicite de l'API
        try:
            challengerep = self._query_freebox_json("get", "login")
        except Exception as exc:
            raise Exception("Aucun challenge n'a pu être récupéré : {}".format(exc))

        self.challenge = challengerep['result']['challenge']


        sessiondata = {'app_id': APPID,
                       "password": make_digest(self.challenge, self.app_token)}
        try:
            self.sessionData = self._query_freebox_json("post", "login/session/", sessiondata)
        except Exception as exc:
            raise Exception("Aucune session n'a pu être récupérée : {}".format(exc))

        self.session_id = self.sessionData['result']['session_token']

    def wifi_interface_up_down(self, do_enable=False):
        """
        Coupe ou allume le wifi
        :param do_enable: default False monte l'interface wifi
        :return: None
        """
        if not self.session_id:
            raise Exception("Vous devez d'abord effectuer un login + session")
    
        if 'settings' not in self.sessionData['result']['permissions'] or not self.sessionData['result']['permissions']['settings']:
            raise Exception("Impossible d'accéder aux settings, voir le menu freebox d'autorisation")
        data = {"enabled": do_enable}
        self._query_freebox_json("put", "wifi/config/", data)



        #cont = requests.put(url, data=json.dumps(data), headers=hdr, verify=False)
        # TODO finir le code ici

    def logout(self):
        """
        ferme la session
        """
        url = "{}login/logout/".format(self.createdurl)
        hdr = {"X-Fbx-App-Auth": self.session_id}
        replogout = requests.post(url, headers=hdr, verify=self.query_verify)
        jsreplogout = replogout.json()

        if replogout.status_code != 200 or not jsreplogout['success']:
            raise Exception("Erreur lors du logout")

    def _query_freebox_json(self, method, url, params=None):
        """
        Requête l'url et retourne le json
        :param method: méthode
        :param url: url à interroger
        :param params: paramètres à passer
        :return: json
        """
        url_fbx = "{}{}".format(self.createdurl, url)
        if self.session_id:
            hdr = {"X-Fbx-App-Auth": self.session_id}
        else:
            hdr = None
        data = json.dumps(params)
        content = None
        if method == "get":
            content = requests.get(url_fbx, data=data, headers=hdr, verify=self.query_verify)
        if method == "post":
            content = requests.post(url_fbx, data=data, headers=hdr, verify=self.query_verify)
        if method == "put":
            content = requests.put(url_fbx, data=data, headers=hdr, verify=self.query_verify)
        if content and content.status_code != 200:
            raise Exception("La requête sur {} a échoué".format(url_fbx))
        jscontent = content.json()
        if not jscontent['success']:
            raise Exception("L'appel REST sur {} a échoué".format(url_fbx))
        return jscontent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""Outil de commande pour le contrôle de la Freebox via son API""")
    parser.add_argument("--wifi_enable", "-W",
                      help="Allume l'interface wifi",
                      default=False, action="store_true")
    parser.add_argument("--wifi_disable", "-w",
                        help="Eteint l'interface wifi",
                        default=False, action="store_true")
    parser.add_argument('--version', action='version', version='%(prog)s '+APPVER)
    args = parser.parse_args()

    fbx = Freebox()
    fbx.get_app_token()
    fbx.login()
    if args.wifi_enable:
        fbx.wifi_interface_up_down(True)
    elif args.wifi_disable:
        fbx.wifi_interface_up_down(False)
    fbx.logout()
