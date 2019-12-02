import unittest
from app import *
from bs4 import BeautifulSoup


class TestCasesFlaskApp(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_home_path(self):
        get_result = self.app.get("/", follow_redirects=True)
        self.assertEqual(get_result.status_code, 200)
        self.assertIn(b"Login", get_result.data)
    
    def test_register_path(self):
        get_result = self.app.get("/register")
        self.assertEqual(get_result.status_code, 200)
        self.assertIn(b"Register", get_result.data)

    def test_login_path(self):
        get_result = self.app.get("/login")
        self.assertEqual(get_result.status_code, 200)
        self.assertIn(b"Login", get_result.data)
    
    def test_spell_check_path(self):
        get_result = self.app.get("/spell_check")
        self.assertEqual(get_result.status_code, 401)
        self.assertIn(b"Unauthorized", get_result.data)

    def register_user(self, uname):
        get_result = self.app.get("/register")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")   
        data = {
            "csrf_token": csrf_token,
            "uname": uname,
            "pword": "testpassword",
            "2fa": "00000000000"
        }
        post_result = self.app.post("/register", data=data)
        self.assertIn(b"Success: Account registered", post_result.data)

    def test_register_user(self):
        uname = "test_user_3"
        self.register_user(uname)

        get_result2 = self.app.get("/register")
        html2 = BeautifulSoup(get_result2.data,"html.parser")
        csrf_token = html2.find(id="csrf_token").get("value")   
        data = {
            "csrf_token": csrf_token,
            "uname": uname,
            "pword": "testpassword",
            "2fa": "00000000000"
        }
        post_result2 = self.app.post("/register", data=data)
        self.assertIn(b"Failure: Username already registered", post_result2.data)

    def logout_user(self):
        self.app.get("/logout", follow_redirects=True)

    def logged_in_user(self, uname):
        self.logout_user()
        get_result = self.app.get("/login")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")  
        data = {
            "csrf_token": csrf_token,
            "uname": uname,
            "pword": "testpassword",
            "2fa": "00000000000"
        }
        post_result = self.app.post("/login", data=data, follow_redirects=True)
        self.assertIn(b"Spell Check", post_result.data)
        self.assertIn(b"Success: User logged in", post_result.data)

    def test_login_valid_credentials(self):
        uname = "test_user_1"
        self.register_user(uname)
        self.logged_in_user(uname)

    def test_login_invalid_credentials(self):
        uname = "test_user_2"
        self.register_user(uname)
        get_result = self.app.get("/login")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")
        data = {
            "csrf_token": csrf_token,
            "uname": uname,
            "pword": "testpassword",
            "2fa": "00000000000"
        }
        original_pword = data["pword"]
        data["pword"] = "wrongpassword"
        data["csrf_token"] = csrf_token
        post_result2 = self.app.post("/login", data=data)
        self.assertIn(b"Failure: Incorrect password", post_result2.data)

        data["pword"] = original_pword
        data["2fa"] = "1-111-111-1111"
        get_result2 = self.app.get("/login")
        html2 = BeautifulSoup(get_result2.data,"html.parser")
        csrf_token = html2.find(id="csrf_token").get("value")
        data["csrf_token"] = csrf_token
        post_result3 = self.app.post("/login", data=data)
        self.assertIn(b"Failure: Incorrect Two-factor", post_result3.data)

        data["uname"] = "not_registered_uname"
        get_result3 = self.app.get("/login")
        html3 = BeautifulSoup(get_result3.data,"html.parser")
        csrf_token = html3.find(id="csrf_token").get("value")
        data["csrf_token"] = csrf_token
        post_result3 = self.app.post("/login", data=data)
        self.assertIn(b"Failure: Incorrect username", post_result3.data)

    def test_empty_fields(self):
        get_result = self.app.get("/register")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")
        data = {
            "csrf_token": csrf_token,
            "uname": "",
            "pword": "",
            "2fa": ""
        }
        post_result = self.app.post("/register", data=data)
        self.assertIn(b"Failure: Empty Field(s)", post_result.data)

        get_result2 = self.app.get("/login")
        html2 = BeautifulSoup(get_result2.data,"html.parser")
        csrf_token = html2.find(id="csrf_token").get("value")
        data["csrf_token"] = csrf_token
        post_result2 = self.app.post("/login", data=data)
        self.assertIn(b"Failure: Empty Field(s)", post_result2.data)

    def test_logout(self):
        uname = "test_user_1"
        self.logged_in_user(uname)
        self.logout_user()
        get_result = self.app.get("/spell_check")
        self.assertEqual(get_result.status_code, 401)
        self.assertIn(b"Unauthorized", get_result.data)

    def test_session_saved_logged_in_user(self):
        uname = "test_user_3"
        self.logged_in_user(uname)
        get_result = self.app.get("/register", follow_redirects=True)
        self.assertIn(b"Spell Check", get_result.data)
        get_result2 = self.app.get("/login", follow_redirects=True)
        self.assertIn(b"Spell Check", get_result2.data)
        get_result3 = self.app.get("/", follow_redirects=True)
        self.assertIn(b"Spell Check", get_result3.data)

    def spell_check(self, uname, inputtext, misspellings):
        self.logged_in_user(uname)
        get_result = self.app.get("/spell_check")
        self.assertIn(b"Spell Check", get_result.data)
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")  
        data = {
            "csrf_token": csrf_token,
            "inputtext": inputtext
        }
        post_result = self.app.post("/spell_check", data=data)
        self.assertIn(inputtext.encode(), post_result.data)
        self.assertIn(misspellings.encode(), post_result.data)

    def test_query_history_as_non_admin(self):
        uname = "test_user_1"
        self.logged_in_user(uname)
        self.spell_check("test_user_1", "mon!ey money Mo3ney", "mon!ey, Mo3ney")

        uname = "test_user_2"
        self.logged_in_user(uname)
        self.spell_check("test_user_2", "pie p!ie pie!", "p!ie")
        self.spell_check("test_user_2", "b1rea2k lunch supper", "b1rea2k")
        
        get_result = self.app.get("/history")
        self.assertIn(b"Number of Query Records: 2", get_result.data)

        query_record_id = "1"
        query_record_id_text = ("Query Record ID " + query_record_id).encode()
        self.assertNotIn(query_record_id_text, get_result.data)
        get_result2 = self.app.get("/history/query" + query_record_id)
        self.assertIn(b"404 Not Found", get_result2.data)

        get_result3 = self.app.get("/history")
        query_record_id2 = "2"
        query_record_id2_text = ("Query Record ID " + query_record_id).encode()
        self.assertNotIn(query_record_id2_text, get_result3.data)
        get_result3 = self.app.get("/history/query" + query_record_id2)
        self.assertIn(b"Query Text: pie p!ie pie!", get_result3.data)

    def test_spell_check(self):
        self.spell_check("test_user_3", "justice just!ice jus!tice", "just!ice, jus!tice")

    def test_login_history_as_non_admin(self):
        uname = "test_user_4"
        self.register_user(uname)
        self.logged_in_user(uname)
        get_result = self.app.get("/login_history")
        self.assertIn(b"Unauthorized", get_result.data)

    def logged_in_admin(self):
        self.logout_user()
        get_result = self.app.get("/login")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value")  
        data = {
            "csrf_token": csrf_token,
            "uname": "admin",
            "pword": "Administrator@1",
            "2fa": "12345678901"
        }
        post_result = self.app.post("/login", data=data, follow_redirects=True)
    
    def test_view_query_as_admin(self):
        self.logged_in_admin()
        get_result = self.app.get("/history")
        self.assertIn(b"Query History", get_result.data)

        query_record_id = "1"
        query_record_id_text = ("Query Record ID " + query_record_id).encode()
        self.assertIn(query_record_id_text, get_result.data)
        get_result2 = self.app.get("/history/query" + query_record_id)
        self.assertIn(b"Query ID: 1", get_result2.data)
        
    def test_login_history_as_admin(self):
        self.logged_in_admin()
        get_result = self.app.get("/login_history")
        self.assertIn(b"Login History", get_result.data)

        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value") 
        existing_userid = "1"
        data = {
            "csrf_token": csrf_token,
            "userid": existing_userid
        }
        post_result = self.app.post("/login_history", data=data)
        userid_text = ("User ID: " + existing_userid).encode()
        self.assertIn(userid_text, post_result.data)
        self.assertIn(b"Login Time:", post_result.data)

        get_result = self.app.get("/login_history")
        html = BeautifulSoup(get_result.data,"html.parser")
        csrf_token = html.find(id="csrf_token").get("value") 
        nonexisting_userid = "1000000"
        data2 = {
            "csrf_token": csrf_token,
            "userid": nonexisting_userid 
        }
        post_result2 = self.app.post("/login_history", data=data2)
        self.assertIn(b"404 Not Found", post_result2.data)


if __name__ == '__main__':
    unittest.main()

