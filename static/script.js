function analyzeRepository() {
    var repoUrl = document.getElementById('repoUrl').value;
    var formData = new FormData();
    formData.append('repo_url', repoUrl);

    fetch('https://code-analysis-tool.onrender.com/analyze', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        displayResults(data);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function displayResults(data) {
    var resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = ''; // Clear previous results

    if (data.total_vulnerability_percentage !== undefined) {
        resultsDiv.innerHTML += "<p>Total vulnerability percentage for the entire project: " + data.total_vulnerability_percentage.toFixed(2) + "%</p>";

        if (data.dependencies) {
            resultsDiv.innerHTML += "<h2>Vulnerability percentages for dependencies:</h2>";
            data.dependencies.forEach(dependency => {
                resultsDiv.innerHTML += "<p>Vulnerability percentage for " + dependency.package_name + ": " + dependency.vulnerability_percentage.toFixed(2) + "%</p>";
            });
        }
    } else if (data.message !== undefined) {
        resultsDiv.innerHTML = "<p>" + data.message + "</p>";
    }
}
