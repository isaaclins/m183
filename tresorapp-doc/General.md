You can find the Repo for the App right [here](https://github.com/hagmannStephan/m183-tresor-app).
The lection plan can be found [here](https://bbw-it.github.io/183_main_rupe/03_Drehbuch/Drehbuch_Modul_183_FS25_22d_PR/).
# Start App
## Start Frontend
1. Open a Terminal in the frontend project
2. `npm install`
3. `npm start`
4. Now you can access the Webpage under [http://localhost:3000/](http://localhost:3000/). However you **also need to start the Backend and & DB** for it to work properly!
## Start Backend & DB
1. Open a Terminal in the backend project
2. `docker compose up db -d` (If you already have the container, you can also just start it)
3. `code .` (VSC should open, but you can also open the folder manually with VSC)
4. Open the File `TresorbackendApplication.java` and press the Play-Icon at the top right of the screen
### Optional: If no Volumes of the DB exsists
1. Install the Extension `PostgreSQL` from `Database Client` (`cweijan.vscode-postgresql-client2)
2. Open the `Database` Tab on the left hand side of the screen in VSC
3. `Create Connection`
4. Enter this data: ![[Pasted image 20250503165951.png]]
5. `Save`
6. Open the file `tresordb.sql` in the `resources` Folder and press the Execute button at the top right side
## Check if everything worked
Open the URL [http://localhost:3000/user/users](http://localhost:3000/user/users) and check if you can see User Entries.