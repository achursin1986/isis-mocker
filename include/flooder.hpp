#pragma once
#include <boost/bind/bind.hpp>

#include "io.hpp"
#include "utils.hpp"

struct FlooderStats {
  long lsp_announced{0};
};

class AsyncRepeater {
public:
  explicit AsyncRepeater(boost::posix_time::seconds period)
      : holdtimer_(timer_, tick_interval_) {
  }
  ~AsyncRepeater() {
    stop();
    timer_th_.join();
  }

  template <typename Callable>
  void start(Callable func) {}
  void stop() {}

private:
  boost::asio::io_context timer_;
  boost::asio::deadline_timer holdtimer_;
  std::thread timer_th_;
  const boost::posix_time::seconds period_;
  const boost::posix_time::seconds tick_interval_{1};
};

class Flooder2 {
public:
  Flooder2(Flooder2& other) = delete;
  Flooder2(Flooder2&& other) = delete;
  Flooder2& operator=(Flooder2&& other) = delete;

  Flooder2(int id, std::unordered_map<std::string, std::string>& lsdb, IO& io,
           std::atomic_bool& state, bool update)
      : lsdb_(lsdb),
        mocker_id_(id),
        io_(io),
        state_(state),
        updatedb_(update),
        repeater_(boost::posix_time::seconds(500)) {
    if (state_) {
      start();
    }
  }

  void start() {
#ifdef DEBUG
    std::cout << "Received start from mocker " << mocker_id_ << std::endl;
    std::cout << "id " << mocker_id_ << "Active: " << active << std::endl;
    std::cout << "id " << mocker_id_ << "Current tick: " << tick_count_
              << std::endl;
#endif
    repeater_.start([this](const boost::system::error_code& e) {
      if (e != boost::asio::error::operation_aborted) {
        this->do_flood();
      }
    })
  }

  void stop() {
#ifdef DEBUG
    std::cout << "Received stop from mocker " << mocker_id_ << std::endl;
#endif
    repeater_.stop();
  }

  FlooderStats& get_stats() { return stats_; }

  ~Flooder2() {}

private:
  void do_flood() {
    for (auto const& [key, value] : lsdb_) {
      boost::asio::streambuf sbuf;
      std::iostream os(&sbuf);
      sbuf.prepare(value.size());
      os << value;
      io_.do_send(&sbuf);
      stats_.lsp_announced++;
      /* hold a bit for router to process */
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      if (updatedb_) incrSequenceNum(lsdb_, key, value);
    }

    IO & io_;
    FlooderStats stats_;
    std::unordered_map<std::string, std::string>& lsdb_;
    // FSM state
    std::atomic_bool& state_;
    std::atomic_bool active{false}, prev{false};
    std::atomic_int tick_count_{};
    bool updatedb_;
    AsyncRepeater repeater_;
  };

  class Flooder {
  public:
    Flooder(Flooder& other) = delete;
    Flooder(Flooder&& other) = delete;
    Flooder& operator=(Flooder&& other) = delete;

    Flooder(int id, std::unordered_map<std::string, std::string>& lsdb, IO& io,
            std::atomic_bool& state, bool update)
        : lsdb_(lsdb),
          mocker_id_(id),
          io_(io),
          state_(state),
          holdtimer_(timer_, boost::posix_time::seconds(tick_interval_)),
          updatedb_(update) {
      timer_th_ = std::thread([&]() {
        holdtimer_.expires_from_now(boost::posix_time::seconds(tick_interval_));
        holdtimer_.async_wait(boost::bind(&Flooder::startTimer, this)),
            timer_.run();
      });

      if (state_) active = true;
      tick_count_ = 500;
    }

    void start() {
#ifdef DEBUG
      std::cout << "Received start from mocker " << mocker_id_ << std::endl;
      std::cout << "id " << mocker_id_ << "Active: " << active << std::endl;
      std::cout << "id " << mocker_id_ << "Current tick: " << tick_count_
                << std::endl;
#endif

      active = true;
      if (active > prev) tick_count_ = 500;
    }
    void stop() {
#ifdef DEBUG
      std::cout << "Received stop from mocker " << mocker_id_ << std::endl;
#endif
      active = false;
      if (active < prev) tick_count_ = 500;
    }

    FlooderStats& get_stats() { return stats_; }

    ~Flooder() {
      terminate = true;
      // holdtimer_.cancel();
      // timer_.stop();
      timer_th_.join();
    }

  private:
    void startTimer() {
      tick_count_++;
      if (active &&
          tick_count_ >
              500 /*&& ec != boost::asio::error::operation_aborted*/) {
        for (auto const& [key, value] : lsdb_) {
          if (terminate) break;
          boost::asio::streambuf sbuf;
          std::iostream os(&sbuf);
          sbuf.prepare(value.size());
          os << value;
          io_.do_send(&sbuf);
          stats_.lsp_announced++;
          /* hold a bit for router to process */
          std::this_thread::sleep_for(std::chrono::milliseconds(5));
          if (updatedb_) incrSequenceNum(lsdb_, key, value);
        }
        tick_count_ = 0;
      }

      if (!active && tick_count_ > 500) tick_count_ = 0;
      if (active)
        prev = true;
      else
        prev = false;
      if (!terminate) {
        holdtimer_.expires_at(holdtimer_.expires_at() +
                              boost::posix_time::seconds(tick_interval_));
        holdtimer_.async_wait(boost::bind(&Flooder::startTimer, this));
      }
    }

    boost::asio::io_context timer_;
    boost::asio::deadline_timer holdtimer_;
    std::thread timer_th_;
    int mocker_id_, tick_interval_{1};
    IO& io_;
    FlooderStats stats_;
    std::unordered_map<std::string, std::string>& lsdb_;
    bool terminate{false};
    // FSM state
    std::atomic_bool& state_;
    std::atomic_bool active{false}, prev{false};
    std::atomic_int tick_count_{};
    bool updatedb_;
  };
