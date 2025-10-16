This is the Linux Build.

This build should primarily be used as a bash command for routine, automatic uploads to Bitwarden.

For the program to work, ensure that you have downloaded the linux version of Bitwarden and that its in the same directory as the .py file.
Also be sure that the Linux binary file has been configured to be run as an executable.

The example bash command would be:

$ python upload_passwords.py <client_id> <client_secret> <bw password | bw password file path> <import method>

where import method is specified by:
    -i <file name> <Organization Name> <Collection Name> : 
        import a whole file specified as <file_name> and overwrite everything that's currently in <collection_name> specified.
        This command is most useful for batch password changes, where the old passwords are no longer in use and need to be written over.
    
        i.e. $ python upload_passwords.py "user.0000...000" "xxxxxxxxx" "mp.txt" -i "passwords.csv" "Super Cool Company" "Super Cool Department"

    -a <file name> :
        This command only adds passwords to the collection as specified in the .csv file that is uploaded.
        As a warning, this takes considerably more time that -i. Due to the nature of Bitwarden's CLI and importing passwords this function interates through each password individually, rather than in batches.

        i.e. $python upload_passwords.py "user.0000...000" "xxxxxxxxx" "mp.txt" -a "passwords.csv"


Using a password file, ensure that the password is the only thing on the first line of the file.
By the recommendation of Bitwarden, "protect [your password file] by locking access down to only the user who needs to run bw unlock and only providing read access to that user." 

CSV Formatting:
    The input format for a CSV file containing passwords for needn't be too complicated. There must be at the following columns:
        - Unit : the name or the title that will be associated with the password on Bitwarden. It is the label of the password.
        - User : the login username.
        - Password : the password of the given username
        - IP address : the IP address (or the domain name) which will be associated with the login information
    
    These must be headers in the CSV file. If not, an error will be thrown. It doesn't matter where they are, as long as they are in the header. Not every logon needs each one of these elements. 



Current additions in development:
    -utilizing Python's pandas as a way to eliminate the need for a strict csv format.
    -improving error messages so as to be descriptive about the solution to the error.
