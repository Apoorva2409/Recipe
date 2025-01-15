package com.example.demo.service;
//
//import com.example.demo.exception.UserNotFoundException;
//import com.example.demo.model.User;
//import com.example.demo.repository.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//
//import java.util.List;
//import java.util.Optional;
//
//@Service
//
public class UserService {
}
//    @Autowired
//    private UserRepository userRepoImpl;
//
//   @Autowired
//   private BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    public User saveUser(User user){
//        return userRepoImpl.save(user);
//    }
//    public User loginUser(String username, String password) {
//        User user = userRepoImpl.findByUsername(username);
//        if (user != null && bCryptPasswordEncoder.matches(password, user.getPassword())) {
//            return user;
//        }
//        return null;
//    }
//
//    public Optional<User> getUserById(Long id ){
//        return Optional.ofNullable(userRepoImpl.findById(id)
//                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id)));
//    }
//
//    public List<User> getAllUser(){
//        return userRepoImpl.findAll();
//    }
//
//    public User updateUser(User user, Long id){
//        if (!userRepoImpl.existsById(id)) {
//            throw new UserNotFoundException("User not found with id: " + id);
//        }
//        return userRepoImpl.save(user);
//    }
//
//    public void deleteUserById(Long id){
//        if (!userRepoImpl.existsById(id)) {
//            throw new UserNotFoundException("User not found with id: " + id);
//        }
//        userRepoImpl.deleteById(id);
//    }
//
//    public void deleteAllUser(){
//        userRepoImpl.deleteAll();
//    }
//}