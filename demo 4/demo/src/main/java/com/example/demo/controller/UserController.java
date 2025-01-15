package com.example.demo.controller;
//
//import com.example.demo.model.User;
//import com.example.demo.service.UserService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.Optional;
//
//@RestController
//@RequestMapping("/api/users")
public class UserController {}
//
//    @Autowired
//    private UserService userServiceImpl;
//
//    @PostMapping("/registers")
//    public User saveData(@RequestBody User user){
//        return userServiceImpl.saveUser(user);
//    }
//
//    @PostMapping("/login")
//    public User loginUser(@RequestBody User user) {
//        User loggedInUser = userServiceImpl.loginUser(user.getUsername(), user.getPassword());
//        if (loggedInUser != null) {
//            return loggedInUser;
//        } else {
//            throw new RuntimeException("Invalid username or password");
//        }
//    }
//
//
//    @GetMapping("/getUserById/{id}")
//    public Optional<User> getUserById(@PathVariable Long id){
//        return userServiceImpl.getUserById(id);
//    }
//
//    @GetMapping("/getAllUser")
//    public List<User> getAllUser(){
//        return userServiceImpl.getAllUser();
//    }
//
//    @PutMapping("/updateUser/{id}")
//    public User updateUser(@RequestBody User user, @PathVariable Long id){
//        return userServiceImpl.updateUser(user, id);
//    }
//
//    @DeleteMapping("/deleteUserById/{id}")
//    public String deleteUserById(@PathVariable Long id){
//        userServiceImpl.deleteUserById(id);
//        return "User Deleted By Id";
//    }
//
//    @DeleteMapping("/deleteAllUser")
//    public String deleteAllUser(){
//        userServiceImpl.deleteAllUser();
//        return "All User Deleted";
//    }
//}
//create a User service
// login will come in security
//config: authFilter, UserService, impl security filters
//Security config: security filter, Authtication and auth, Password encoder,authentication provider,
//Create a class which should only take username and password
//create a class Jwt Authetication filter
