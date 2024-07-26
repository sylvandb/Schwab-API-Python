""" token management for schwab client API """
import json
import base64
import requests
from sys import stdin
import threading
import time
from . import color_print
from datetime import datetime



class TokenUpdateError(Exception): pass



class Token:

    def __init__(self, lifetime):
        self.lifetime = lifetime
        self.issued = None
        self._token = None

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self.issued = datetime.now()
        self._token = value

    @property
    def expires(self):
        # return seconds until expiration, lifetime - age
        try:
            return self.lifetime - (datetime.now() - self.issued).total_seconds()
        except TypeError:
            return 0



class Tokens:

    def __init__(self,
        app_key, app_secret,
        callback_url="https://127.0.0.1",
        tokens_file="tokens.json",
        verbose=True,
        webbrowser=False,
        auto_refresh=True):
        """
        Token management for the Schwab API.
        :param app_key: app key credentials
        :type app_key: str
        :param app_secret: app secret credentials
        :type app_secret: str
        :param callback_url: url for callback
        :type callback_url: str
        :param tokens_file: path to tokens file
        :type tokens_file: str
        :param verbose: print extra information
        :type verbose: bool
        :param webbrowser: okay to launch webbrowser
        :type webbrowser: bool
        :param auto_refresh: automatically acquire the refresh token
        :type auto_refresh: bool
        """

        if callback_url is None or tokens_file is None:
            raise Exception("callback_url and tokens_file cannot be None.")
        elif len(app_key) != 32 or len(app_secret) != 16:
            raise Exception(f"Invalid length App key({len(app_key)}) or app secret({len(app_secret)}).")

        self._app_key = app_key
        self._app_secret = app_secret
        self._callback_url = callback_url
        self._access_token = Token(1800)       # in seconds (from schwab)
        self._refresh_token = Token(7 * 86400) # days (from schwab) to seconds
        self._token_thread = None
        self._token_usable = 60             # minimum seconds to consider token usable
        self._auto_refresh = auto_refresh   # automatically attempt to acquire a refresh token
        self._tokens_file = tokens_file     # path to tokens file
        self._verbose = verbose             # verbose mode
        self._webbrowser = webbrowser       # okay to open a webbrowser

        self.id_token = None

        try:
            self._read_tokens_file()
        except:
            # The tokens file doesn't exist, so create it.
            color_print.warning(f"Token file does not exist or invalid formatting, creating \"{str(self._tokens_file)}\"")
            open(self._tokens_file, 'w').close()
        else:
            # show user when tokens were last updated and when they will expire
            if self._verbose:
                color_print.info(self._access_token.issued.strftime(
                    "Access  token last updated: %Y-%m-%d %H:%M:%S") + f" (expires in {int(self._access_token.expires)} seconds)")
                color_print.info(self._refresh_token.issued.strftime(
                    "Refresh token last updated: %Y-%m-%d %H:%M:%S") + f" (expires in {self._refresh_token.expires/86400:0.2f} days)")


    @property
    def access_token(self):
        return self._access_token.token

    @property
    def token_expires(self):
        return self._refresh_token.expires


    def update_tokens_auto(self):
        """
        Spawns a thread to check the access token and update if necessary
        """
        if self._token_thread:
            return
        first = threading.Event()
        first.clear()
        def checker():
            while self._token_thread:
                try:
                    self.update_tokens()
                except Exception as e:
                    color_print.error(f"Error during update_tokens: {e}")
                first.set()
                time.sleep(self._token_usable)
        self._token_thread = threading.Thread(target=checker, daemon=True)
        self._token_thread.start()
        first.wait()


    def update_tokens(self):
        """
        Checks if tokens need to be updated and updates if needed (only access token is automatically updated)
        """
        # check if we need to update refresh (and access) token - if less than 1s before expiration
        rte = self._refresh_token.expires
        rtem = ''
        if rte < 1:
            rtem = "The refresh token has expired, "
            for i in range(3):  color_print.user(f"{rtem}please update!")
            if self._auto_refresh:
                self.acquire_refresh_token()
        # check if we need to update access (and refresh?) token - if less than 60s before expiration
        if self._access_token.expires < self._token_usable:
            if self._verbose:
                color_print.info(f"The access token has expired, {rtem}updating automatically.")
            self._update_access_token()
        # else: color_print.info("Token check passed")


    def acquire_refresh_token(self):
        """
        Get new access and refresh tokens using authorization code.
        """
        if not self._webbrowser and not stdin.isatty():
            msg="Unable to update refresh token: no webbrowser and not a tty!"
            color_print.error(msg)
            raise TokenUpdateError(msg)
        # get authorization code (requires user to authorize)
        color_print.user("Please authorize this program to access your schwab account.")
        auth_url = f'https://api.schwabapi.com/v1/oauth/authorize?client_id={self._app_key}&redirect_uri={self._callback_url}'
        color_print.user(f"Click to authenticate: {auth_url}")
        if self._webbrowser:
            import webbrowser
            color_print.user("Opening browser...")
            webbrowser.open(auth_url)
        response_url = color_print.user_input(
            "After authorizing, wait for it to load (<1min) and paste the WHOLE url here: ")
        code = f"{response_url[response_url.index('code=') + 5:response_url.index('%40')]}@"  # session = responseURL[responseURL.index("session=")+8:]
        # get new access and refresh tokens
        response = self._post_oauth_token('authorization_code', code)
        if response.ok:
            # update token file and variables
            new_td = response.json()
            self.id_token = new_td.get("id_token")
            self._access_token.token = new_td.get("access_token")
            self._refresh_token.token = new_td.get("refresh_token")
            self._write_tokens_file(new_td)
            color_print.info("Refresh and Access tokens updated")
        else:
            color_print.error("Could not get new refresh and access tokens, check these:\n    1. App status is "
                              "\"Ready For Use\".\n    2. App key and app secret are valid.\n    3. You pasted the "
                              "whole url within 30 seconds. (it has a quick expiration)")
            raise TokenUpdateError("Could not acquire refresh token.")


    def _update_access_token(self):
        """
        "refresh" the access token using the refresh token
        """
        # get new tokens
        for i in range(3):
            response = self._post_oauth_token('refresh_token', self._refresh_token.token)
            if response.ok:
                # get and update to the new access token
                new_td = response.json()
                self.id_token = new_td.get("id_token")
                self._access_token.token = new_td.get("access_token")
                refresh_token = new_td.get("refresh_token")
                if refresh_token and refresh_token != self._refresh_token.token:
                    self._refresh_token.token = refresh_token
                    color_print.info(f"Refresh token updated: {self._refresh_token.issued}")
                self._write_tokens_file(new_td)
                # update the lifetime in case schwab decides to change it
                self._access_token.lifetime = new_td.get("expires_in", self._access_token.lifetime)
                # show user that we have updated the access token
                if self._verbose:
                    color_print.info(f"Access token updated: {self._access_token.issued} for {self._access_token.lifetime} seconds")
                break
            else:
                color_print.error(f"Could not get new access token ({i+1} of 3).")
                time.sleep(i ** 2)
        else:
            raise TokenUpdateError("Could not get new access token.")


    def _post_oauth_token(self, grant_type, code):
        """
        Makes API calls for auth code and refresh tokens
        """
        headers = {
            'Authorization': f'Basic {base64.b64encode(bytes(f"{self._app_key}:{self._app_secret}", "utf-8")).decode("utf-8")}',
            'Content-Type': 'application/x-www-form-urlencoded'}
        if grant_type == 'authorization_code':  # gets access and refresh tokens using authorization code
            data = {'grant_type': 'authorization_code', 'code': code,
                    'redirect_uri': self._callback_url}
        elif grant_type == 'refresh_token':  # refreshes the access token
            data = {'grant_type': 'refresh_token', 'refresh_token': code}
        else:
            color_print.error("Invalid grant type")
            return None
        return requests.post('https://api.schwabapi.com/v1/oauth/token', headers=headers, data=data)


    def _write_tokens_file(self, tokenDictionary):
        """
        Writes token file
        :param tokenDictionary: token dictionary
        :type tokenDictionary: dict
        """
        try:
            with open(self._tokens_file, 'w') as f:
                toWrite = {
                    "access_token_issued": self._access_token.issued.isoformat(),
                    "refresh_token_issued": self._refresh_token.issued.isoformat(),
                    "token_dictionary": tokenDictionary}
                json.dump(toWrite, f, ensure_ascii=False, indent=4)
                f.flush()
        except Exception as e:
            color_print.error(e)
            # continue on as normal


    def _read_tokens_file(self):
        """
        Reads token file
        """
        try:
            with open(self._tokens_file, 'r') as f:
                d = json.load(f)
            token_dictionary = d.get("token_dictionary")
            # update the lifetime in case schwab decides to change it
            self._access_token.lifetime = token_dictionary.get("expires_in", self._access_token.lifetime)
            self._access_token.token = token_dictionary.get("access_token")
            self._access_token.issued = datetime.fromisoformat(d.get("access_token_issued"))
            # any way we can tell a new refresh token lifetime?
            self._refresh_token.token = token_dictionary.get("refresh_token")
            self._refresh_token.issued = datetime.fromisoformat(d.get("refresh_token_issued"))
            self.id_token = token_dictionary.get("id_token")
        except Exception as e:
            color_print.error(e)
            raise
