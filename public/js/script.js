console.log("script.js loaded successfully");

document.addEventListener('DOMContentLoaded', async () => {
    const currentPage = window.location.pathname;

    if (currentPage === '/technician-dashboard.html') {
        // Placeholder technician ID - replace with actual logic to get the logged-in technician's ID
        const technicianId = 'technician1'; 

        // Fetch and display jobs for the technician
        fetch(`/api/technician/jobs?technicianId=${technicianId}`)
            .then(response => response.json())
            .then(jobs => {
                const jobList = document.getElementById('job-list');
                const acceptedJobList = document.getElementById('job-list-accepted');
                if (jobList) {
                    jobs.forEach(job => {
                        if (job.status === 'Pending') {
                            createJobListItem(job, jobList);
                        } else if (job.status === 'Accepted' && acceptedJobList) {
                            createJobListItem(job, acceptedJobList);
                        }
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching technician jobs:', error);
            });
    } else if (currentPage === '/admin-dashboard.html') {
        // Fetch and display all users for the admin dashboard
        fetch('/api/admin/users')
            .then(response => response.json())
            .then(users => {
                const userList = document.getElementById('user-list');
                if (userList) {
                    users.forEach(user => {
                        // Skip the admin user from the list for granting roles
                        if (user.role === 'admin') {
                            return;
                        }

                        const listItem = document.createElement('li');
                        listItem.dataset.userId = user.id; // Add user ID to the list item

 if (user.role !== 'technician' && user.role !== 'admin') {
 const grantButton = document.createElement('button');
 grantButton.classList.add('grant-technician-btn');
 grantButton.textContent = 'Grant Technician Role';
 grantButton.dataset.userId = user.id; // Add user ID to the button
 listItem.appendChild(grantButton);
 }
 listItem.innerHTML += `
                            User ID: ${user.id}, Phone: ${user.phoneNumber || 'N/A'}, Email: ${user.email || 'N/A'}, Role: ${user.role}
                        `;
                        userList.appendChild(listItem);
                    });
                }



            })
            .catch(error => {
                console.error('Error fetching users for admin dashboard:', error);
            });
    }

    // Login form submission handler (moved inside DOMContentLoaded)
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const email = document.getElementById('login-email').value.trim();
            const password = document.getElementById('login-password').value;

            // Show loading state
            const submitBtn = e.target.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Logging in...';

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (data.success) {
                    // Redirect based on the URL provided by the server
                    if (data.redirect) {
                        window.location.href = data.redirect; // Use the redirect URL from the server
                    } else {
                        console.warn('Login successful but no redirect URL provided by server.');
                        window.location.href = '/'; // Default to homepage if no redirect
                    }
                } else {
                    throw new Error(data.message || 'Login failed');
                }

            } catch (error) {
                console.error('Error:', error);
                alert(error.message || 'An error occurred during login');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }
        });
    }
});

// Function to create a job list item (extracted for potential updates)
function createJobListItem(job, jobListElement) {
    const jobList = document.getElementById('job-list');
    if (jobList) {
        const listItem = document.createElement('li');
 listItem.dataset.jobId = job.id; // Add job ID to the list item
        listItem.innerHTML = `
            Job ID: ${job.id}, Appliance: ${job.applianceType}, Location: ${job.location}, Status: <span>${job.status}</span>
        `;

        if (job.status === 'Pending') {
            const acceptButton = document.createElement('button');
            acceptButton.classList.add('accept-job-btn');
            acceptButton.textContent = 'Accept Job';
            listItem.appendChild(acceptButton);
        } else if (job.status === 'Accepted') {
            const diagnosisLink = document.createElement('a');
            diagnosisLink.href = `/diagnosis?jobId=${job.id}`;
            diagnosisLink.textContent = 'Perform Diagnosis';
            listItem.appendChild(diagnosisLink);
        }

        // Append to the correct job list element
        if (jobListElement) {
            jobListElement.appendChild(listItem);
        }
    }
}

// Event listener for accepting jobs
document.addEventListener('click', (event) => {
    if (event.target.classList.contains('accept-job-btn')) {
        const jobId = event.target.dataset.jobId;
        fetch('/api/technician/jobs/accept', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jobId })
        }).then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update the job status on the page
                    const listItem = event.target.closest('li');
                    if (listItem) {
                        const statusSpan = listItem.querySelector('span');
                        if (statusSpan) {
                            statusSpan.textContent = 'Accepted';
                            event.target.remove(); // Remove the accept button

                            // Add the "Perform Diagnosis" link
                            const diagnosisLink = document.createElement('a');
                            diagnosisLink.href = `/diagnosis?jobId=${jobId}`;
                            diagnosisLink.textContent = 'Perform Diagnosis';
                            listItem.appendChild(diagnosisLink);
                        }
                    }
                    console.log('Job accepted:', data.message);
                } else {
                    console.error('Failed to accept job:', data.message);
                }
            })
            .catch(error => {
                console.error('Error accepting job:', error);
            });
    }
});

// Function to handle granting technician role
document.addEventListener('click', async (event) => {
    if (event.target.classList.contains('grant-technician-btn')) {
        const userId = event.target.dataset.userId;
        try {
            const response = await fetch(`/api/admin/users/${userId}/grant-technician`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId }) // Sending userId in the body as well for consistency
            });
            const data = await response.json();
            if (data.success) {
                alert(`Role granted successfully for user ${userId}.`);
                // You might want to refresh the user list or update the specific list item here
                event.target.closest('li').querySelector('span').textContent = 'technician'; // Update role text
                event.target.remove(); // Remove the button
            } else {
                alert(`Failed to grant role: ${data.message}`);
            }
        } catch (error) {
            console.error('Error granting technician role:', error);
            alert('An error occurred while granting the technician role.');
        }
    }
});
