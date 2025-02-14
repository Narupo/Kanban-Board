import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  // TODO: make a POST request to the login route

  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userInfo)
  });

  if (!response.ok) {
    throw new Error('Invalid API response');
  }

  const data = await response.json();
  console.log("Token Data", data);
  return data;
}



export { login };
