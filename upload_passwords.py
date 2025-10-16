import subprocess
import pandas as pd
import time, re
import sys, os

#This is the Linux build. 

#This is the PATH for the Bitwarden CLI. This needs to be correct in order for the rest of the program to run.
#The easiest way to do this is to have it in the same directory as this file, or to put bw in /usr/local/bin.

if "bw" in os.listdir():
    BW = "./bw"
else:
    BW = "bw"

templates = {
    "item" : "",
    "login" : "",
}

#Assures that files are formatted correctly
def verify_genetec_csv(file, debug = False):
    with open(file) as f:
        columns = f.readline().split(",")
        if debug:
            print(columns)
        assert columns[0].strip() == "Password"
        assert columns[1].strip() == "Unit"
        assert columns[8].strip() == "IP address"
        assert columns[10].strip() == "User"
    return True

def verify_bitwarden_csv(file):
    with open(file) as f:
        rest = f.readlines()
        columns = rest[0].split(",")
        assert columns[0] == "collections"
        assert columns[1] == "type"
        assert columns[2] == "name"
        assert columns[3] == "notes"
        assert columns[4] == "fields"
        assert columns[5] == "reprompt"
        assert columns[6] == "login_uri"
        assert columns[7] == "login_username"
        assert columns[8] == "login_password"
        assert columns[9] == "login_totp\n"
        collections = []
        for line in rest[1:]:
            collection = line.split(",")[0]
            if collection not in collections:
                collections.append(collection)
    #makes sure that there is only one collection that we will be adding to.
    assert len(collections) == 1
    return True, collections

#This function assumes that you want every password to be added to a new collection labeled according to <COLLECTION_NAME>
#returns the file path to a bitwarden compatible csv, and also an array of the collections that will be created by importing this file.
def write_bitwarden_csv(genetec_csv, new_file):
    try:
        assert verify_genetec_csv(genetec_csv)
        print("File is compatible with bitwarden.")
        with open(genetec_csv, "r") as f:
            with open(new_file, "w") as nf:
                nf.write("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n")
                lines = f.readlines()
                for line in lines[1:-1]:
                    camera = [c.strip() for c in line.split(",")]
                    #for some reason, vivotek has another comma at one point, so this is for that.
                    if camera[2] == "Vivotek":
                        nf.write(f"{COLLECTION_NAME},login,{camera[1]},,,,https://{camera[9]}/,{camera[11]},{camera[0]},\n")
                    else:
                        nf.write(f"{COLLECTION_NAME},login,{camera[1]},,,,https://{camera[8]}/,{camera[10]},{camera[0]},\n")
                camera = lines[-1].split(",")
                if camera[2] == "Vivotek":
                    nf.write(f"{COLLECTION_NAME},login,{camera[1]},,,,https://{camera[9]}/,{camera[11]},{camera[0]},")
                else:
                    nf.write(f"{COLLECTION_NAME},login,{camera[1]},,,,https://{camera[8]}/,{camera[10]},{camera[0]},")
        print(f"File converted to: {new_file}")

    except FileNotFoundError:
        print(f"File could not be found: {genetec_csv}")
        quit()
    except AssertionError:
        try:
            is_bitwarden_file, collections = verify_bitwarden_csv(genetec_csv)
            if is_bitwarden_file:
                print("File is compatible with bitwarden.")
                return genetec_csv
            else:
                assert False
        except AssertionError:
            print("Data in the Genetec CSV file is mislabeled. Cannot convert to Bitwarden CSV.")
            verify_genetec_csv(genetec_csv, True)
            quit()
    return new_file 

#The abstracted way to interact with Bitwarden's CLI
def cmd_prompt(commands, inputs = [], delay = 2):
    prompt = subprocess.Popen(commands,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for i in inputs:
        prompt.stdin.write(f"{i}\n")
        prompt.stdin.flush()
        time.sleep(delay)
    
    output = prompt.communicate()
    
    return output[0], output[1]

def login_to_bitwarden(attempt = 0):
    #inputs correct info for unlocking the account and gets session key
    try:
        login, login_err = cmd_prompt([BW, "login", "--apikey"],[CLIENT_ID, CLIENT_SECRET], delay= 3 + attempt)
        if "client_id or client_secret is incorrect. Try again." in login_err:
            raise ValueError(login_err)
        elif "You are not logged in" in login_err:
            if attempt < 3:
                print(f"Login failed, will attempt to login {'two' if attempt == 1 else 'one'} more {'times' if attempt == 1 else 'time'}.")
                return login_to_bitwarden(attempt = attempt + 1)
            else:
                raise ValueError("Attempted and failed to log in three times.")
        else:
            print("You are logged in!")
            unlock, unlock_err = cmd_prompt([BW, "unlock"], [BW_PASSWORD])
            SESSION_KEY = unlock.split('"')[1]
            print(f"Session key obtained: {SESSION_KEY}")
    except ValueError as e:
        print("The client information that was given is incorrect.\nCorrect info can be found at bitwarden.com after logging in, under Settings > Security > API Key.")
        quit()
    except IndexError:
        print(f"IndexError: {unlock, unlock_err}")
        quit()
    except OSError:
        logout()
        SESSION_KEY = login_to_bitwarden()
    return SESSION_KEY

def logout():
    print(cmd_prompt([BW, "logout"])[0])

#Returns needed information based off given inputs
def get_organization_id(org_name):
    text, err = cmd_prompt([BW, "list", "organizations", "--session", SESSION_KEY])
    expression = '(?<="id":").{36}(?=","name":"' + f'{org_name}")'
    finds = re.findall(expression, text)
    if len(finds) < 1:
        raise ValueError("Organization name not in Bitwarden.")
    elif len(finds) > 1:
        raise ValueError("There appear to be two organizations of the same name. Rename them so there are unique names for each organization.")
    else:
        return finds[0]

def get_collection_id(organization_id, collection_name):
    text, err = cmd_prompt([BW, "list", "org-collections", "--organizationid", organization_id, "--session", SESSION_KEY])
    expression = '(?<="id":").{36}(?=",".{56}' + f'name":"{collection_name}")'
    finds = re.findall(expression, text)

    if len(finds) < 1:
        raise TypeError("Collection name not in organization.")
    elif len(finds) > 1:
        raise ValueError("There appear to be two collections of the same name. Rename them so there are unique names for each collection.")
    else:
        return finds[0]

def get_access_ids(collection_id, organization_id):
    text, err = cmd_prompt([BW, "get", "org-collection",collection_id, "--organizationid", organization_id, "--session", SESSION_KEY])
    groups_expression = '(?<="groups":\\[).*(?=],"users":)'
    groups = re.findall(groups_expression, text)
    users_expression = '(?<="users":\\[).*(?=])'
    users = re.findall(users_expression, text)

    if len(groups) + len(users) < 1:
        raise TypeError("This collection appears to have no groups or users attached to it.")
    else:
        return groups, users

#This will import all the items in the associated file to the same collection, specified by <COLLECTION_NAME> - used by "-i"
def import_to_bitwarden(file, delete_old_collection = False, add_previous_user_groups = False):
    csv_path = write_bitwarden_csv(file, "bitwarden_ready.csv")
    groups = ""
    users = ""
    collection_id = ""

    #gets organization ids
    try:
        organization_id = get_organization_id(ORGANIZATION_NAME)
        print(f"Organization found. \nOrganization: {organization_id}")
    except ValueError as e:
        print(e)
        return 0
    
    #copies down previous user groups from the collection named <COLLECTION_NAME>
    if add_previous_user_groups:
        try:
            collection_id = get_collection_id(organization_id, COLLECTION_NAME)
            print(f"Collection found.\nCollection: {collection_id}")
            groups, users = get_access_ids(collection_id, organization_id)
        except (TypeError, ValueError) as e:
            print(e)
            if e == "This collection appears to have no groups attached to it.":
                add_previous_user_groups = False
                delete_old_collection = False #because the old colleciton doesn't exist.

    #deletes old collection according to delete_old_collection
    if delete_old_collection:
        try:
            #get collection id if we haven't already found it.
            if len(collection_id) == 0:
                collection_id = get_collection_id(organization_id, COLLECTION_NAME)
                print(f"Collection found.\nCollection: {collection_id}")
            cmd_prompt([BW, "delete", "org-collection", collection_id, "--organizationid", organization_id, "--session", SESSION_KEY])
            print("Old collection deleted.")
        except Exception as e:
            print(f"Collection was not deleted correctly.\n\t{e}")

    #imports new file
    try:
        commands = [BW, "import", "--organizationid", organization_id, "bitwardencsv", csv_path, "--session", SESSION_KEY]
        import_file, import_err = cmd_prompt(commands)
        if len(import_file) < 4:
            raise Exception(import_err)
        else:
            print("File Imported: ", import_file)

    except Exception as e:
        print("File was not imported correctly.\n" + str(e))

    if add_previous_user_groups:
        new_collection_id = get_collection_id(organization_id, COLLECTION_NAME)
        json = cmd_prompt([BW, "get", "org-collection", new_collection_id, "--organizationid", organization_id, "--session", SESSION_KEY])[0]
        json = json.replace('"groups":[]', f'"groups":[{groups[0] if len(groups) > 0 else ""}]')
        json = json.replace('"users":[]', f'"users":[{users if len(users) > 0 else ""}]')

        encode = cmd_prompt([BW, "encode"], [json])[0]
        edit, error = cmd_prompt([BW, "edit", "org-collection", new_collection_id, "--organizationid", organization_id, "--session", SESSION_KEY], [encode])

        if len(error) > 0:
            print("Permissions were not added correctly. Be sure that they are added properly.")
        else:
            print("Permissions added correctly.")

#These two "add_password" functions combined make "-a" work.
def add_password(name, uris, username, password, collectionid, organizationid):

    login = templates["login"].replace('"uris":[]', ('"uris":[{"uri":"' + uris + '"}]'))
    login = login.replace('"username":"jdoe"', f'"username":"{username}"')
    login = login.replace('"password":"myp@ssword123"', f'"password":"{password}"')

    password = templates["item"].replace('"organizationId":null', f'"organizationId": "{organizationid}"')
    password = password.replace('"collectionIds":null', f'"collectionIds":["{collectionid}"]')
    password = password.replace('"name":"Item name"', f'"name":"{name}"')
    password = password.replace('"login":null', f'"login":{login}')

    encode = cmd_prompt([BW, "encode"], [password])
    create = cmd_prompt([BW, "create", "item", "--session", SESSION_KEY], [encode])

def add_passwords_from_csv(genetec_csv):
    #standardize data according to bitwarden's needs
    file_name = write_bitwarden_csv(genetec_csv, "bitwarden_ready.csv")

    #find json templates. 
    templates["item"], template_error1 = cmd_prompt([BW, "get", "template", "item", "--session", SESSION_KEY])
    templates["login"], template_error1 = cmd_prompt([BW, "get", "template", "item.login", "--session", SESSION_KEY])
    print("Found item templates.")
    
    organization_id = get_organization_id(ORGANIZATION_NAME)
    collection_ids = {}
    
    total_passwords = 0
    failed_passwords = []

    with open(file_name) as f:
        lines = f.readlines()
    for line in lines[1:]:
        password = line.split(",")
        #check to see if it's collection_id has already been found:
        if password[0] not in collection_ids:
            print(f"Collection ID not in Dictionary: {password[0]}")
            try:
                collection_ids[password[0]] = get_collection_id(organization_id, password[0])
            except TypeError:
                #Add collection if the collection doesn't exist.
                templates["collection"] = cmd_prompt([BW, "get", "template", "collection", "--session", SESSION_KEY])

                new_collection = templates["collection"].replace('"organizationId":"00000000-0000-0000-0000-000000000000"', f'"organizationId":"{organization_id}"')
                new_collection = new_collection.replace('"name":"Collection name"', f'"name":"{password[0]}"')

                encode, encode_error = cmd_prompt([BW, "encode"], [new_collection])
                create, create_error = cmd_prompt([BW, "create", "org-collection", "--organizationid", f"{organization_id}", "--session", SESSION_KEY], [encode])

                collection_ids[password[0]] = get_collection_id(organization_id, password[0])
        try:
            add_password(password[2], password[6], password[7], password[8], collection_ids[password[0]], organization_id)
            print(f"Password (\"{password[2]}\") created.")
            total_passwords += 1
        except Exception as e:
            print(f"Failed to create password (\"{password[2]}\") due to the following error: \n\t{e}")
            failed_passwords.append(password[2])

    print(f"Successfully added {total_passwords} {'password' if total_passwords == 1 else 'passwords'} to Bitwarden.")
    print(f"Failed to add the following {'password' if len(failed_passwords) == 1 else 'passwords'}: {failed_passwords}")

if __name__ == "__main__":
    arguments = sys.argv
    if arguments[4] == "-i":
        if len(arguments) != 8:
            print("Invalid CL arguments.")
            quit()
    elif arguments[4] == "-a":
        if len(arguments) != 6:
            print("Invalid CL arguments")
            quit()

    CLIENT_ID = arguments[1]
    CLIENT_SECRET = arguments[2]
    mp_file = arguments[3]

    try:
        with open(mp_file) as f:
            BW_PASSWORD = f.readline().strip() #Master Password for your Account.
    except FileNotFoundError:
        print(f"File {mp_file} could not be found. Attempting to use given argument as the password.")
        BW_PASSWORD = mp_file

    import_method = arguments[4]
    password_file = arguments[5]

    SESSION_KEY = login_to_bitwarden()

    if import_method == "-i":
        ORGANIZATION_NAME = arguments[6]
        COLLECTION_NAME = arguments[7]
        import_to_bitwarden(password_file, delete_old_collection=True, add_previous_user_groups=True)
    if import_method == "-a":
        add_passwords_from_csv(password_file)
    
    logout()