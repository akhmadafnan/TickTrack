<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterStoreRequest;

class AuthController extends Controller
{
    // public function login(Request $request)
    // {
    //     try {

    //         Log::info('Login attempt:', [
    //             'email' => $request->email,
    //             'password_length' => strlen($request->password)
    //         ]);

    //         $credentials = $request->only('email', 'password');

    //         if (!Auth::guard('web')->attempt($request->only('email', 'password'))) {
    //             return response()->json([
    //                 'message' => 'Unauthorized',
    //                 'data' => null
    //             ], 401);
    //         }

    //         $user = Auth::user();
    //         $token = $user->createToken('auth_token')->plainTextToken;

    //         return response()->json([
    //             'message' => 'Login berhasil',
    //             'data' => [
    //                 'token' => $token,
    //                 'user' => $user
    //             ]
    //         ], 200);
    //     } catch (Exception $e) {
    //         return response()->json([
    //             'message' => 'Terjadi kesalahan',
    //             'error' => $e->getMessage(),
    //             'data' => null
    //         ], 500);
    //     }
    // }

    public function login(Request $request)
    {
        // SIMPLE DEBUG DI RESPONSE
        $debugInfo = [
            'received_email' => $request->input('email', 'NOT FOUND'),
            'received_password' => $request->input('password', 'NOT FOUND') ? '***' : 'NULL',
            'all_data' => $request->all(),
            'content_type' => $request->header('Content-Type')
        ];

        // AMBIL DATA LANGSUNG
        $email = $request->input('email');
        $password = $request->input('password');

        // VALIDASI MANUAL SANGAT SIMPLE
        if (empty($email)) {
            return response()->json([
                'success' => false,
                'message' => 'Email wajib diisi',
                'debug' => $debugInfo,
                'data' => null
            ], 422);
        }

        if (empty($password)) {
            return response()->json([
                'success' => false,
                'message' => 'Password wajib diisi',
                'debug' => $debugInfo,
                'data' => null
            ], 422);
        }

        // CARI USER - PAKAI EMAIL YANG ADA DI DATABASE
        // Email di database: "admin@ticktrack.com"
        $user = User::where('email', $email)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User tidak ditemukan',
                'debug' => [
                    'email_looking_for' => $email,
                    'user_in_db' => User::first() ? User::first()->email : 'NO USERS'
                ],
                'data' => null
            ], 401);
        }

        // CEK PASSWORD - PASTIKAN COCOK
        $passwordCorrect = Hash::check($password, $user->password);

        if (!$passwordCorrect) {
            return response()->json([
                'success' => false,
                'message' => 'Password salah',
                'debug' => [
                    'email' => $email,
                    'password_tried' => $password,
                    'password_length' => strlen($password),
                    'db_hash_start' => substr($user->password, 0, 20)
                ],
                'data' => null
            ], 401);
        }

        // GENERATE TOKEN
        try {
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'Login berhasil!',
                'data' => [
                    'token' => $token,
                    'user' => new UserResource($user)
                ]
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal membuat token',
                'error' => $e->getMessage(),
                'data' => null
            ], 500);
        }
    }

    public function me()
    {
        try {
            $user = Auth::user();

            return response()->json([
                'message' => 'Profile user berhasil diambil',
                'data' => new UserResource($user)
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal membuat token',
                'error' => $e->getMessage(),
                'data' => null
            ], 500);
        }
    }

    // public function logout()
    // {
    //     try {
    //         $user = Auth::user();
    //         $user->currentAccessToken()->delete();

    //         return response()->json([
    //             'message' => 'Logout berhasil',
    //             'data' => null
    //         ], 200);
    //     } catch (\Exception $e) {
    //         return response()->json([
    //             'success' => false,
    //             'message' => 'Gagal membuat token',
    //             'error' => $e->getMessage(),
    //             'data' => null
    //         ], 500);
    //     }
    // }

    public function logout(Request $request) // <-- TAMBAHKAN Request $request
    {
        try {
            $user = $request->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User tidak terautentikasi atau token sudah expired'
                ], 401);
            }

            $currentToken = $user->currentAccessToken();

            if (!$currentToken) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tidak ada token aktif'
                ], 400);
            }

            $currentToken->delete();

            return response()->json([
                'success' => true,
                'message' => 'Logout berhasil',
                'data' => null
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal logout',
                'error' => $e->getMessage(),
                'data' => null
            ], 500);
        }
    }

    public function register(RegisterStoreRequest $request)
    {
        DB::beginTransaction();

        try {
            $validated = $request->validated();

            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => Hash::make($validated['password']),
                'role' => 'user'
            ]);

            $token = $user->createToken('auth_token')->plainTextToken;

            DB::commit();

            return response()->json([
                'message' => 'Registrasi berhasil',
                'data' => [
                    'token' => $token,
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role
                    ]
                ]
            ], 201);
        } catch (\Exception $e) {
            DB::rollBack();

            return response()->json([
                'success' => false,
                'message' => 'Registrasi gagal',
                'error' => $e->getMessage(),
                'data' => null
            ], 500);
        }
    }
}
