<?php
// Intentionally vulnerable Laravel controller (academic SAST target).
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function show(Request $request)
    {
        $name = $request->input('name');
        $users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'"); // VULN: SQL injection

        echo $name;                                                             // VULN: reflected XSS

        $host = $request->get('host');
        system("ping -c1 " . $host);                                            // VULN: command injection

        return view('user', ['users' => $users]);
    }

    public function safe(Request $request)
    {
        $id = (int) $request->input('id');                                      // cast -> safe
        $users = DB::select("SELECT * FROM users WHERE id = ?", [$id]);         // parameterized -> safe

        echo e($request->input('name'));                                        // escaped -> safe
        return view('user', ['users' => $users]);
    }
}
