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
Route::prefix('v1')->group(function(){
    Route::post('register',[AuthController::class,'register']);
    Route::post('login', [AuthController::class, 'login']);
    Route::post('verify-email/{id}/{hash}', [AuthController::class, 'verify'] );
});

Route::post("/v1/message", function (Request $request) {
    $message = $_POST['message'];
    $mqService = (new RabbitMQService());
    $mqService->publish($message);
    return view('welcome');
});



