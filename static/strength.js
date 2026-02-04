// Password Strength Meter
function checkStrength() {
    const passwordInput = document.getElementById("password");
    const strengthText = document.getElementById("strength");
    
    if (!passwordInput || !strengthText) return;
    
    const password = passwordInput.value;
    
    let score = 0;
    const feedback = [];
    
    // Check password length
    if (password.length >= 8) score++;
    else feedback.push("At least 8 characters");
    
    // Check for uppercase letters
    if (/[A-Z]/.test(password)) score++;
    else feedback.push("One uppercase letter");
    
    // Check for lowercase letters
    if (/[a-z]/.test(password)) score++;
    else feedback.push("One lowercase letter");
    
    // Check for numbers
    if (/[0-9]/.test(password)) score++;
    else feedback.push("One number");
    
    // Check for special characters
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score++;
    else feedback.push("One special character");
    
    // Determine strength level
    let strength = "Weak";
    let color = "red";
    
    if (score === 5) {
        strength = "Very Strong";
        color = "darkgreen";
    } else if (score === 4) {
        strength = "Strong";
        color = "green";
    } else if (score === 3) {
        strength = "Good";
        color = "orange";
    } else if (score === 2) {
        strength = "Fair";
        color = "goldenrod";
    } else {
        strength = "Weak";
        color = "red";
    }
    
    // Update display
    strengthText.innerHTML = `
        <strong>Password Strength: <span style="color: ${color}">${strength}</span></strong>
        ${feedback.length > 0 ? `<br><small>Missing: ${feedback.join(", ")}</small>` : ''}
    `;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById("password");
    if (passwordInput) {
        passwordInput.addEventListener('keyup', checkStrength);
        passwordInput.addEventListener('change', checkStrength);
    }
});