# CryptoTrade — Shared Manager Backend (తెలుగు)

ఈ projectలో మీ ప్రస్తుత CryptoTrade HTML design‌ను అలాగే ఉంచి, registration/login మరియు manager users list‌ను ఒకే online PostgreSQL database‌కు కనెక్ట్ చేశాం.

## ఇది ఏమి చేస్తుంది?
- ఏ మొబైల్‌లో register చేసినా user వివరాలు ఒకే databaseలో సేవ్ అవుతాయి.
- మొదటి కొత్త User ID `6000`; ఆ తర్వాత 6001, 6002… ఇలా server క్రమంగా ఇస్తుంది. ఒకేసారి ఇద్దరు register చేసినా IDలు repeat కావు.
- Manager panel ప్రతి 10 సెకన్లకు shared database నుంచి కొత్త registrations‌ను refresh చేస్తుంది.
- Manager login credentials server environment‌లో ఉంటాయి; HTMLలో manager password hard-code చేయలేదు.
- Passwordలు databaseలో plain textగా కాక bcrypt hashగా మాత్రమే ఉంటాయి.
- Status, demo balance, demo score, invite code manager changes shared databaseకు పంపబడతాయి.
- ఇది practice/demo platform మాత్రమే; real-money trading/payment backend కాదు.

## ముఖ్యమైన పరిమితి
ఈ projectకి Render Web Serviceతో పాటు PostgreSQL database అవసరం. కేవలం HTMLని GitHub Pagesలో ఉంచితే shared backend పనిచేయదు. HTMLని ఈ Render service నుంచే serve చేసేలా ఉంచాం. మొదటిసారి deploy చేసిన తర్వాత Render URLనే website URLగా ఉపయోగించండి.

## Renderలో setup — Android ఫోన్ నుంచీ
1. ఈ ZIPని extract చేయండి.
2. మొత్తం `CryptoTrade_Shared` folderను మీ GitHub repositoryకి upload చేయండి. `package.json`, `server.js`, `public/index.html`, `make-manager-hash.js` optional file మాత్రమే.
3. Renderలో PostgreSQL database create చేయండి; దాని **Internal Database URL**ని copy చేయండి.
4. Renderలో **New + → Web Service** ఎంచుకుని ఆ GitHub repositoryని connect చేయండి.
5. Root Directory ఖాళీగా ఉంచండి (లేదా project folder rootగా ఉండేలా repo పెట్టండి). Build Command: `npm install`. Start Command: `npm start`.
6. Web Service → Environmentలో ఈ variables జోడించండి:
   - `DATABASE_URL` = Render PostgreSQL Internal Database URL
   - `JWT_SECRET` = పొడవైన random secret (కనీసం 32 అక్షరాలు)
   - `MANAGER_USERNAME` = మీరు కోరుకునే manager username
   - `MANAGER_PASSWORD` = మీరు ఎంచుకునే బలమైన, ప్రత్యేకమైన manager password (ఈ valueను Render Environmentలో మాత్రమే పెట్టండి)
   - `DATABASE_SSL` = `true`
7. Save Changes / Deploy చేయండి. Manager username/passwordను వెబ్‌సైట్ HTMLలో పెట్టకండి; Render Environmentలో మాత్రమే ఉంచండి. Logsలో `CryptoTrade backend listening` కనిపించాలి.
8. Render ఇచ్చిన `https://....onrender.com` URL తెరవండి. Register చేసి ID `6000` వచ్చిందో పరీక్షించండి. మరో ఫోన్‌లో వేరే usernameతో register చేయండి; manager panelలో రెండు accounts కనిపించాలి.

## గమనికలు
- ఈ buildలో user profile/trade history వంటి పాత demo featuresలో కొన్నివి ఇంకా ప్రతి browserలో localStorage ఆధారంగా ఉండవచ్చు. Shared registration, login, manager user list, status/demo balance/demo score/invite code మాత్రం backend ద్వారా sync అవుతాయి.
- Manager panelలో password చూపించము. Manager accountను మీరే సురక్షితంగా ఉంచండి.
- Productionలో ఉపయోగించే ముందు backup, rate limiting, HTTPS మరియు security review చేయించండి.
