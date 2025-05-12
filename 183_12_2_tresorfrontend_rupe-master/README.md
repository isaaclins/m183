# The secret tresor application frontend

## Technik

- basiert auf React

## Umgebungsvariablen

- In der **Datei .env** sind die von der Applikation **verwendeten Umgebungsvariablen** deklariert.
- Falls die Umgebungsvariablen _aussen_ nicht gesetzt sind, wird ein Default-Wert verwendet.

## Hinweise zur Anwendung der Applikation

- Die Applikation ist für den Unterricht gedacht.
- Die vorliegende Version hat keine Security implementiert.
- So spielt das Passwort (noch) keine Rolle.

- Wenn die Applikation gestartet ist, kann man mit</br>
  _Admin->All user_</br>
  Vom Backend das Verzeichnis aller User abrufen.

- Mit</br>
  _User->Register_</br>
  Kein ein neuer User via Backend gespeichert werden
- Danach ist ein Login des Users notwendig.</br>
  _User->Login_ mit Email und Passwort</br>
  Diese Login-Daten sind für die _Secrets_ Funktionen notwendig.
- Es können drei unterschiedliche Secrets gespeicher werden.
- Und es können die eigenen Secrets abgerufen werden.

## Build image

see Dockerfile

```Bash
docker build -t tresorfrontendimg .
```

## Start container local

```Bash
docker run -p 80:80 --name tresorfrontend tresorfrontendimg

(c) 2024 P. Rutschmann

