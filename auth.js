import {
  startRegistration,
  startAuthentication,
} from 'https://cdn.skypack.dev/@simplewebauthn/browser';

export async function register() {
  const username = document.getElementById('username').value;

  // Begin registration process to get options
  let optionsRes = await fetch('/register/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });

  let options = await optionsRes.json();
  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start registration
  let attestation = await startRegistration(options);

  // Send attestation response to server
  let verificationRes = await fetch('/register/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      attestationResponse: attestation,
    }),
  });
  let verificationResult = await verificationRes.json();
  let x=`Login ${verificationResult ? 'successful' : 'failed'}`;
  if(x==`Login successful`){
    window.location.href = '/successReg.html';
  }else{
    alert(`Login ${verificationResult ? 'successful' : 'failed'}`);}
}
export async function login() {
  const username = document.getElementById('username').value;
  
  // Begin authentication process to get options
  let optionsRes = await fetch('/login/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });
  let options = await optionsRes.json();

  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start authentication
  console.log(options);

  let assertion = await startAuthentication(options);

  // Send assertion response to server
  let verificationRes = await fetch('/login/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      assertionResponse: assertion,
    }),
  });
  
  let verificationResult = await verificationRes.json();
  let x=`Login ${verificationResult ? 'successful' : 'failed'}`;
  if(x==`Login successful`){
    window.location.href = '/success.html?username=' + encodeURIComponent(username);
  }else{
    alert(`Login ${verificationResult ? 'successful' : 'failed'}`);}
}


try{
  document.getElementById('authSignUp').addEventListener('click', register);
}
catch{  document.getElementById('authSignIn').addEventListener('click', login);
}

document.getElementById('loginButton').addEventListener('click', () => {
    window.location.href = '/auth/google';
});
document.getElementById('gitbutton').addEventListener('click', () => {
    window.location.href = '/auth/github';
});



// auth.js

// Make sure to import the methods from @simplewebauthn/browser at the beginning of this script file
