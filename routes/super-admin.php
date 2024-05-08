<?php

use Illuminate\Http\Request;
use App\Services\RabbitMQService;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\RoomController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::group(['prefix'=>'super-admin', 'middleware'=>['auth:jwt']], function(){
    Route::get('room', [RoomController::class, 'index']);
    Route::post('room', [RoomController::class, 'store']);

});



