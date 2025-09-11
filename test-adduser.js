import fetch from 'node-fetch';

const testAddUser = async () => {
    const userData = {
        username: "testuser123",
        password: "password123",
        email: "testuser123@example.com",
        mobile: "1234567890",
        name: "Test User",
        role: "user",
        location: "Test Location",
        roles: JSON.stringify({ "1": { "name": "User" } })
    };

    try {
        const response = await fetch('http://localhost:3003/adduser', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });

        const data = await response.json();
        console.log('Response:', data);
    } catch (error) {
        console.error('Error:', error);
    }
};

testAddUser(); 