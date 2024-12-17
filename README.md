# Setup Instructions
1. Install Laravel 11:
```shell
composer create-project laravel/laravel jwt-auth-app
php artisan migrate
```

2. Install laravel-jwt-auth for handling JWTs:
```shell
composer require tymon/jwt-auth
```

3. Publish the JWT configuration file:
```shell
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
php artisan jwt:secret
```

# Generate RSA Keys for JWT

1. Generate RSA private and public keys:
```shell
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```

2. Move the keys to a secure directory, e.g., storage/oauth/:
```shell
mv private.key storage/oauth/
mv public.key storage/oauth/
```

 # Update JWT Config to Use RSA Keys:

In config/jwt.php, configure JWT to use the RSA keys:

```shell
'secret' => env('JWT_SECRET'), // This is ignored when using RSA keys
'keys' => [
    'public' => storage_path('oauth/public.key'),
    'private' => storage_path('oauth/private.key'),
    'passphrase' => null, // Add passphrase if your private key has one
],
```

# Implement Authentication System
 ### 1. User Model Update:
   Update app/Models/User.php to include JWT traits:

```shell
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password'];

    // JWT Methods
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }
}

```
 ### 2. Create AuthController:
   Create the controller:
```shell
php artisan make:controller AuthController
```
 Create the controller:
```shell
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Models\User;

class AuthController extends Controller
{
    // Register
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'message' => 'User successfully registered',
            'token' => $token,
            'user' => $user,
        ], 201);
    }

    // Login
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        return response()->json([
            'message' => 'Login successful',
            'token' => $token,
            'user' => auth()->user(),
        ]);
    }

    // Change Password
    public function changePassword(Request $request)
    {
        $request->validate([
            'current_password' => 'required',
            'new_password' => 'required|string|min:8|confirmed',
        ]);

        $user = auth()->user();

        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json(['error' => 'Current password is incorrect'], 403);
        }

        $user->update(['password' => Hash::make($request->new_password)]);

        return response()->json(['message' => 'Password changed successfully']);
    }

    // Logout
    public function logout()
    {
        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json(['message' => 'Successfully logged out']);
    }

    // Refresh Token
    public function refresh()
    {
        return response()->json([
            'token' => JWTAuth::refresh(),
        ]);
    }
}

```
 ### 3. Define API Routes:

install api routes for laravel 11

```shell
php artisan install:api
```
Update routes/api.php with these routes:
```shell
use App\Http\Controllers\AuthController;

Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);

Route::middleware('auth:api')->group(function () {
    Route::post('change-password', [AuthController::class, 'changePassword']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::get('refresh', [AuthController::class, 'refresh']);
});

```
 ### 4. Middleware for JWT Authentication:
 Ensure jwt.auth middleware is set up correctly in bootstrap/app.php:
```shell
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Global Middleware
        $middleware->append([
            \Illuminate\Foundation\Http\Middleware\PreventRequestsDuringMaintenance::class,
            \Illuminate\Http\Middleware\HandleCors::class,
        ]);

        // Alias Middleware for Routes
        $middleware->alias([
            'auth' => \App\Http\Middleware\Authenticate::class,
            'auth:api' => \Tymon\JWTAuth\Http\Middleware\Authenticate::class,
            'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
            // 'custom' => \App\Http\Middleware\CustomMiddleware::class, // Example custom middleware
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        // Custom exception handling (if needed)
    })
    ->create();
```

 ### 5. Testing the API:
 1. Register: POST /api/register:
  ```shell
{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123",
    "password_confirmation": "password123"
}

```
 2. Login: POST /api/login:
 ```shell
{
    "email": "john@example.com",
    "password": "password123"
}

```
 3. Change Password: POST /api/change-password (Authenticated):
 ```shell
{
    "current_password": "password123",
    "new_password": "newpassword123",
    "new_password_confirmation": "newpassword123"
}
```


