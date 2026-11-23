<div class="profile">
    {{-- Auto-escaped output (safe) --}}
    <p>Welcome, {{ $name }}</p>

    {{-- Raw, unescaped output of user input (VULN: stored/reflected XSS) --}}
    <p>Bio: {!! $_GET['bio'] !!}</p>
</div>
