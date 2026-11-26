<?php
// Route table for the academic Laravel SAST target.
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

Route::get('/users', [UserController::class, 'show']);
Route::get('/users/safe', [UserController::class, 'safe']);
